
const express = require('express');
const fetch = require('node-fetch');
const cors = require("cors");
const axios = require("axios");
const app = express();
const port = process.env.PORT || 3000;
const APP_ID = '1264796100052780';
const APP_SECRET = 'f5f7690390494c247d52a27692c7ed2c';
const ACCESS_TOKEN = `OC|${APP_ID}|${APP_SECRET}`;
const expectedPackageName = 'com.IresLLC.IresTag';
const expectedCertHash = '35800750f4fb52ce8a45ca8158e021590df93bf1bbfdf74edc503388c065fe11';
app.use(express.json());

/**
 * Decodes a base64url-encoded JSON string.
 * @param {string} input - Base64url-encoded string.
 * @returns {Object} - Decoded JSON object.
 */
function decodeBase64Url(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return JSON.parse(Buffer.from(input, 'base64').toString('utf8'));
}

app.post('/attestation', async (req, res) => {
  const { token, nonce } = req.body;

  console.log('Verifying with Meta:', { token, nonce });

  if (!token || !nonce) {
    return res.status(400).json({ status: 'error', message: 'Missing token or nonce' });
  }

  try {
    const url = `https://graph.oculus.com/platform_integrity/verify?token=${token}&access_token=${ACCESS_TOKEN}`;
    console.log(`Fetching attestation from Meta: ${url}`);
    const response = await fetch(url);
    const result = await response.json();
    let data = result.data;
    if (Array.isArray(data)) {
      data = data[0];
    }
    const message = data?.message;
    if (message !== 'success') {
      return res.status(401).json({ status: 'invalid', message: 'Attestation failed', meta: result });
    }
    let claimsPayload = null;
    if (typeof data.claims === 'string') {
      try {
        claimsPayload = decodeBase64Url(data.claims);
      } catch (e) {
        console.error('Failed to decode claims:', e);
        return res.status(400).json({ status: 'error', message: 'Malformed claims data', meta: result });
      }
    } else {
      return res.status(400).json({ status: 'error', message: 'No claims found in Meta response', meta: result });
    }
    const appState = claimsPayload.app_state;
    const deviceState = claimsPayload.device_state;
    const certMatch = appState?.package_cert_sha256_digest?.some((cert) => cert.toLowerCase() === expectedCertHash.toLowerCase());

    if (appState?.app_integrity_state !== 'StoreRecognized' || appState?.package_id !== expectedPackageName || !certMatch || deviceState?.device_integrity_state !== 'Advanced') {
      return res.status(401).json({
        status: 'invalid',
        message: 'payload integrity checks failed',
        claims: claimsPayload
      });
    }
    return res.status(200).json({
      status: 'valid',
      message: 'Attestation verified and claims accepted',
      claims: claimsPayload
    });

  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(500).json({ status: 'error', message: 'Internal server error', error: error.message });
  }
});

app.get('/', (req, res) => {
  res.send('ofc your here... yes this game has attestation.');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
