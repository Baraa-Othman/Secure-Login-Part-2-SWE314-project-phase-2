const express = require("express");
const path = require("path");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const database = require("./database/database.js");
const crypto = require("crypto");
const cookieParser = require('cookie-parser');
const querystring = require('querystring');
const secret = require('./client_secret.json');
const session = require("express-session");
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');

const app = express();
const port = 3000;
const CLIENT_ID = secret.client_id;
const CLIENT_SECRET = secret.client_secret;
const REDIRECT_URI = 'http://localhost:3000/auth/google/callback';

// WebAuthn/Passkey specific settings
const rpName = 'SWE314 Secure Authentication';
const rpID = 'localhost';
const origin = `http://${rpID}:3000`;

app.use(session({
  secret: "btet87o34BBV78cb7DrbfFrrt89JJfbqwtu",
  resave: false,
  saveUninitialized: true
}));

app.use(cookieParser());
app.use(express.static('public'));

// OAuth request 
app.get('/auth/google', (req, res) => {
  const authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  const params = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online'
  };
  res.redirect(`${authorizationUrl}?${querystring.stringify(params)}`);
});

// Handle OAuth 2 callback
app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('Authorization code is missing');
  }
  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: querystring.stringify({
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });

    if (!tokenResponse.ok) {
      throw new Error(JSON.stringify(await tokenResponse.json()));
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    if (!accessToken) {
      throw new Error('Access token is missing in the response');
    }

    res.cookie('token', accessToken, { httpOnly: true });
    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

// Dashboard 
app.get('/dashboard', async (req, res) => {
  if (!req.cookies.token) {
    return res.status(401).send('Unauthorized');
  }
  const accessToken = req.cookies.token;

  const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });

  if (!userInfoResponse.ok) {
    throw new Error('Failed to fetch user info');
  }

  const userData = await userInfoResponse.json();
  console.log('<<THIS IS FOR DEBUGGING>>');
  console.log('User Data:', userData);
  console.log('By OAuth2');

  res.send(`
    <div style="display: flex; justify-content: center; align-items: center; height: 100vh; background: linear-gradient(to bottom, #2c2c2c, #1a1a1a); color: #fff; font-family: Arial, sans-serif; text-align: center;">
      <div>
        <h1 style="margin-bottom: 20px; font-size: 2.5rem;">You signed in successfully!</h1>
        <h2 style="margin-bottom: 10px; font-size: 1.5rem;">Email: ${userData.email}</h2>
        <h2 style="margin-bottom: 20px; font-size: 1.5rem;">Name: ${userData.name}</h2>
        <img src="${userData.picture}" alt="Profile Picture" style="border-radius: 50%; width: 150px; height: 150px; border: 3px solid #fff;" />
      </div>
    </div>
  `);
});

const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes window
  max: 5,                   // limit to 5 requests per windowMs
  delayMs: 5000,            // 5 seconds delay between requests
  message: "Too many login attempts from this IP, please try again later."
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use('/', express.static(path.join(__dirname, 'public', 'login')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup')));
app.use('/login', express.static(path.join(__dirname, 'public', 'login')));

// Decryption function for 2FA secret
function decryptSecret(encryptedSecret) {
  const key = crypto.scryptSync("supersecretkey", "salt", 32); // Ensure the correct key length
  const iv = Buffer.alloc(16, 0); // 16-byte IV for AES-256-CBC
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encryptedSecret, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Signup Route with 2FA
app.post('/submitSignup', async (req, res) => {
  const { username, password } = req.body;

  // Generate 2FA secret
  const secret = speakeasy.generateSecret({ length: 20 });
  console.log("Generated Secret (Signup):", secret.base32);

  try {
    // Create user with hashed password and encrypted 2FA secret
    await database.signup({
      username,
      password,
      twoFactorSecret: secret.base32
    });

    console.log(`User ${username} registered with secret: ${secret.base32}`);

    // Generate QR code for 2FA setup
    const otpauth_url = `otpauth://totp/${username}?secret=${secret.base32}&issuer=SWE314-Assignment1`;
    QRCode.toDataURL(otpauth_url, (err, qrImage) => {
      if (err) {
        console.error("QR Code Error:", err);
        return res.status(500).json({ error: "Error generating QR code" });
      }
      res.json({
        message: "User created! Please scan the QR code with your authenticator app",
        qrImage,
        manualEntryCode: secret.base32 // For manual entry option
      });
    });
  } catch (err) {
    console.error("Signup Error:", err);
    res.redirect('/signup?error=true');
  }
});

// Login Route with 2FA Verification
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password, token } = req.body;

  try {
    // First authenticate with username/password
    const user = await database.authenticate({ username, password });

    if (user.length > 0) {
      const encryptedSecret = user[0].twoFactorSecret;
      const secret = decryptSecret(encryptedSecret);
      console.log("<<THIS IS FOR DEBUGGING>>");
      console.log("Stored Secret (Decrypted):", secret);//for debugging
      console.log("Received Token:", token);//for debugging
      console.log(user[0]); //for debugging

      // Verify 2FA token
      const verified = speakeasy.totp.verify({
        secret,
        encoding: "base32",
        token,
        window: 0 // 30-second window
      });

      if (verified) {
        res.json({
          success: true,
          message: "Login successful!",
          user: {
            id: user[0].id,
            username: user[0].username
          }
        });
      } else {
        res.redirect('/?error=true');
      }
    } else {
      res.redirect('/?error=true');
    }
  } catch (err) {
    console.error("Login Error:", err);
    res.redirect('/?error=true');
  }
});

// Create new routes for WebAuthn/Passkey authentication
app.get('/generate-registration-options', async (req, res) => {
  const userName = req.query.userName;

  if (!userName) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    // Ensure user exists or create a new one
    await database.getUserByUsername(userName);

    // Get existing authenticators for this user
    const userAuthenticators = await database.getWebAuthnCredential(userName);

    // Build excludeCredentials array to prevent duplicates
    let excludeCredentials = [];

    if (userAuthenticators && userAuthenticators.length > 0) {
      for (const auth of userAuthenticators) {
        try {
          excludeCredentials.push({
            id: Buffer.from(auth.credentialID, 'base64'),
            type: 'public-key',
            transports: ['internal', 'platform', 'usb', 'ble', 'nfc'],
          });
        } catch (err) {
          console.error('Error processing credential ID for exclusion:', auth.credentialID, err);
        }
      }
    }

    // Generate registration options
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(userName), // Use Buffer for userID
      userName,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform'
      },
      supportedAlgorithmIDs: [-7, -257]
    });

    // Store options in session for verification later
    req.session.currentChallenge = options.challenge;
    req.session.userName = userName;

    return res.json(options);
  } catch (error) {
    console.error('Error generating registration options:', error);
    return res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

app.post('/verify-registration', async (req, res) => {
  const body = req.body;
  const userName = body.userName;
  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({
      verified: false,
      error: 'No challenge found in session. Please try again.'
    });
  }

  try {
    // Verify the registration response
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      try {
        console.log('registrationInfo:', registrationInfo);
        const { credential } = registrationInfo;
        const credentialIDString = credential.id;
        const publicKeyString = isoBase64URL.fromBuffer(credential.publicKey);
        const counter = credential.counter;
        console.log('Saving credential with ID:', credentialIDString);

        // Save the credential
        await database.saveWebAuthnCredential({
          username: userName,
          credentialID: credentialIDString,
          publicKey: publicKeyString,
          counter,
        });

        return res.json({ verified: true });
      } catch (dbError) {
        console.error('Database error during registration:', dbError);

        // If it's a unique constraint error, it's not a critical problem
        if (dbError.code === 'SQLITE_CONSTRAINT') {
          return res.json({
            verified: true,
            message: 'This credential has already been registered'
          });
        }

        return res.status(500).json({
          verified: false,
          error: 'Error saving credential'
        });
      }
    }

    return res.json({
      verified: false,
      error: 'Verification failed'
    });
  } catch (error) {
    console.error('Error during registration verification:', error);
    return res.status(500).json({
      verified: false,
      error: error.message
    });
  }
});

app.get('/generate-authentication-options', async (req, res) => {
  const userName = req.query.userName;

  if (!userName) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    // Ensure user exists (will be created if not)
    await database.getUserByUsername(userName);

    // Get user's authenticators
    const authenticators = await database.getWebAuthnCredential(userName);

    // If no authenticators, ask user to register
    if (!authenticators || authenticators.length === 0) {
      return res.status(400).json({ error: 'No authenticators registered for this user. Please register a passkey first.' });
    }

    // Skip problematic credential conversion and create options manually
    const challenge = crypto.randomBytes(32);
    const options = {
      challenge: isoBase64URL.fromBuffer(challenge),
      timeout: 60000,
      rpID,
      userVerification: 'preferred',
      allowCredentials: []
    };

    // Manually add credential IDs to avoid type conversion issues
    for (const auth of authenticators) {
      try {
        options.allowCredentials.push({
          id: auth.credentialID, // This is a base64url string
          type: 'public-key',
          transports: ['internal', 'platform', 'usb', 'ble', 'nfc'],
        });
      } catch (err) {
        console.error('Error processing credential ID:', auth.credentialID, err);
      }
    }

    // Store the challenge for verification
    req.session.currentChallenge = options.challenge;
    req.session.userName = userName;

    return res.json(options);
  } catch (error) {
    console.error('Error generating authentication options:', error);
    return res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

app.post('/verify-authentication', async (req, res) => {
  const body = req.body;
  const userName = body.userName;
  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({
      verified: false,
      error: 'No challenge found in session. Please try again.'
    });
  }

  try {
    // Get user's authenticators
    const authenticators = await database.getWebAuthnCredential(userName);

    if (!authenticators || authenticators.length === 0) {
      return res.status(400).json({ error: 'No authenticators registered for this user' });
    }

    // The credential ID from the client comes as base64url encoded
    const credentialIdFromClient = body.id;

    console.log('credentialIdFromClient:', credentialIdFromClient);
    console.log('Available credential IDs:', authenticators.map(a => a.credentialID));

    // Try direct match
    let authenticator = authenticators.find(authr => authr.credentialID === credentialIdFromClient);

    // If not found, try comparing as Buffers (handles subtle encoding issues)
    if (!authenticator) {
      try {
        const clientBuf = Buffer.from(credentialIdFromClient, 'base64');
        authenticator = authenticators.find(authr => {
          try {
            return Buffer.from(authr.credentialID, 'base64').equals(clientBuf);
          } catch (e) {
            return false;
          }
        });
      } catch (e) {
        // ignore
      }
    }

    if (!authenticator) {
      console.error('Authenticator not found. Client sent ID:', credentialIdFromClient);
      console.error('Available credential IDs:', authenticators.map(a => a.credentialID));
      return res.status(400).json({ error: 'Authenticator not found' });
    }

    console.log('Authenticator object:', authenticator);

    try {
      // Verify the authentication response
      const verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: authenticator.credentialID,
          publicKey: Buffer.from(authenticator.publicKey, 'base64'),
          counter: parseInt(authenticator.counter || 0, 10),
        },
        requireUserVerification: true,
      });

      const { verified, authenticationInfo } = verification;

      if (verified) {
        // Update the authenticator's counter in database
        await database.updateWebAuthnCounter(
          authenticator.credentialID,
          authenticationInfo.newCounter
        );

        // Set session for the authenticated user
        req.session.user = userName;
        req.session.authenticated = true;

        return res.json({ verified: true });
      }

      return res.json({
        verified: false,
        error: 'Authentication failed'
      });
    } catch (verifyError) {
      console.error('Error during verification:', verifyError);

      // Provide a user-friendly error
      return res.json({
        verified: false,
        error: 'Authentication failed. Please try again.'
      });
    }
  } catch (error) {
    console.error('Error during authentication verification:', error);
    return res.status(500).json({
      verified: false,
      error: error.message
    });
  }
});

// Passkey authentication success route
app.get('/passkey-success', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/');
  }

  res.send(`
    <div style="display: flex; justify-content: center; align-items: center; height: 100vh; background: linear-gradient(to bottom, #2c2c2c, #1a1a1a); color: #fff; font-family: Arial, sans-serif; text-align: center;">
      <div>
        <h1 style="margin-bottom: 20px; font-size: 2.5rem;">Successfully authenticated with Passkey!</h1>
        <h2 style="margin-bottom: 20px; font-size: 1.5rem;">Username: ${req.session.user}</h2>
        <p style="font-size: 1.2rem;">You have securely logged in using WebAuthn/Passkey technology.</p>
      </div>
    </div>
  `);
});

function base64urlToUint8Array(base64urlString) {
  let base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const str = atob(base64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; ++i) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
