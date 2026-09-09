const express = require('express');

const fetch = require('node-fetch');

const app = express();

const port = process.env.PORT || 3000;

const APP_ID = '1264796100052780';

const APP_SECRET = 'f5f7690390494c247d52a27692c7ed2c';

const ACCESS_TOKEN = `OC|${APP_ID}|${APP_SECRET}`;

const expectedPackageName = 'com.IresLLC.IresTag';

const expectedCertHash = '35800750f4fb52ce8a45ca8158e021590df93bf1bbfdf74edc503388c065fe11';

const passedWebhook = 'https://discord.com/api/webhooks/1532446842502250678/Pp6GfxBEatb3yAVm4W15IsdA6C4Ic5uvAfzMRPfqFoTCtoQzPPpNhykyZGdZYAYnuib2';

const failedWebhook = 'https://discord.com/api/webhooks/1532446989889966163/JLibn8NznDNNF3VmDz1EOBGi8tIOgKT9Eca2U56HeOpVgS3V8pEkUB9ETkIcNxeQb2O7';

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

async function sendWebhook(webhook, title, description, color, fields = []) {
  try {
    await fetch(webhook, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        embeds: [
          {
            title: title,
            description: description,
            color: color,
            fields: fields,
            timestamp: new Date().toISOString(),
            footer: {
              text: 'ires tag attestation'
            }
          }
        ]
      })
    });
  } catch (error) {
    console.error('failed to send discord webhook:', error);
  }
}

/**
 * Fetches user information from Meta Graph API
 * @param {string} userId - The Oculus user ID from claims
 * @returns {Object} - User information (username, org_scoped_id, id)
 */
async function fetchMetaUserInfo(userId) {
  try {
    if (!userId || userId === 'undefined' || userId === 'null') {
      console.error('Invalid userId provided to fetchMetaUserInfo:', userId);
      return {
        metaUsername: 'unknown',
        metaUserId: 'unknown',
        orgScopedId: 'unknown'
      };
    }

    const url = `https://graph.oculus.com/${userId}?fields=id,name,username,org_scoped_id&access_token=${ACCESS_TOKEN}`;
    console.log(`Fetching user info from Meta: ${url}`);
    const response = await fetch(url);
    const data = await response.json();
    
    console.log('Meta API Response:', JSON.stringify(data, null, 2));
    
    if (data.error) {
      console.error('Error fetching user info:', data.error);
      return {
        metaUsername: 'unknown',
        metaUserId: userId || 'unknown',
        orgScopedId: 'unknown'
      };
    }

    const username = data.username || data.name || 'unknown';
    const id = data.id || userId || 'unknown';
    const orgScopedId = data.org_scoped_id || 'unknown';

    console.log(`Extracted - Username: ${username}, ID: ${id}, OrgScopedID: ${orgScopedId}`);

    return {
      metaUsername: username,
      metaUserId: id,
      orgScopedId: orgScopedId
    };
  } catch (error) {
    console.error('Failed to fetch user info:', error);
    return {
      metaUsername: 'unknown',
      metaUserId: userId || 'unknown',
      orgScopedId: 'unknown'
    };
  }
}

app.post('/attestation', async (req, res) => {
  const {
    token,
    nonce,
    oculusUserId,
    oculusUsername,
    orgScopedId
  } = req.body;

  console.log('Verifying with Meta:', { 
    token: token ? `${token.substring(0, 30)}...` : 'missing', 
    nonce,
    oculusUserId,
    oculusUsername,
    orgScopedId
  });

  if (!token || !nonce) {
    await sendWebhook(
      failedWebhook,
      'attestation failed',
      'the attestation request was missing a token or nonce.',
      16776960,
      [
        {
          name: 'token',
          value: token ? 'provided' : 'missing',
          inline: true
        },
        {
          name: 'nonce',
          value: nonce ? 'provided' : 'missing',
          inline: true
        },
        {
          name: 'Oculus Username',
          value: oculusUsername || 'unknown',
          inline: true
        },
        {
          name: 'OrgScopedID',
          value: orgScopedId || 'unknown',
          inline: true
        },
        {
          name: 'Challenge Nonce',
          value: nonce || 'unknown',
          inline: true
        }
      ]
    );

    return res.status(400).json({ status: 'error', message: 'Missing token or nonce' });
  }

  try {
    const url = `https://graph.oculus.com/platform_integrity/verify?token=${token}&access_token=${ACCESS_TOKEN}`;
    console.log(`Fetching attestation from Meta: ${url}`);
    const response = await fetch(url);
    const result = await response.json();
    
    console.log('Full attestation response:', JSON.stringify(result, null, 2));
    
    let data = result.data;
    if (Array.isArray(data)) {
      data = data[0];
    }
    const message = data?.message;
    
    let claimsPayload = null;
    let metaUsername = oculusUsername || 'unknown';
    let metaUserId = oculusUserId || 'unknown';
    let metaOrgScopedId = orgScopedId || 'unknown';

    if (typeof data.claims === 'string') {
      try {
        claimsPayload = decodeBase64Url(data.claims);
        console.log('Decoded claims:', JSON.stringify(claimsPayload, null, 2));
        
        // If we didn't get user info from Unity, try to extract from claims
        if (!oculusUserId || oculusUserId === 'unknown') {
          const userIdFromClaims = claimsPayload.user_id || 
                                  claimsPayload.oculus_user_id || 
                                  claimsPayload.sub || 
                                  claimsPayload.aud;
          
          if (userIdFromClaims && userIdFromClaims !== 'undefined' && userIdFromClaims !== 'null') {
            const userInfo = await fetchMetaUserInfo(userIdFromClaims);
            metaUsername = userInfo.metaUsername;
            metaUserId = userInfo.metaUserId;
            metaOrgScopedId = userInfo.orgScopedId;
          }
        }
      } catch (e) {
        console.error('Failed to decode claims:', e);
        await sendWebhook(
          failedWebhook,
          'attestation failed',
          'the claims data could not be decoded.',
          16776960,
          [
            {
              name: 'decode error',
              value: e.message || 'unknown error'
            },
            {
              name: 'Oculus Username',
              value: metaUsername || 'unknown',
              inline: true
            },
            {
              name: 'OrgScopedID',
              value: metaOrgScopedId || 'unknown',
              inline: true
            },
            {
              name: 'Challenge Nonce',
              value: nonce || 'unknown',
              inline: true
            }
          ]
        );
        return res.status(400).json({ status: 'error', message: 'Malformed claims data', meta: result });
      }
    } else {
      console.error('No claims string found in data');
      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'no claims were found in the meta response.',
        16776960,
        [
          {
            name: 'meta response',
            value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\``
          },
          {
            name: 'Oculus Username',
            value: metaUsername || 'unknown',
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId || 'unknown',
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce || 'unknown',
            inline: true
          }
        ]
      );
      return res.status(400).json({ status: 'error', message: 'No claims found in Meta response', meta: result });
    }

    console.log('Final Meta Info - Username:', metaUsername);
    console.log('Final Meta Info - User ID:', metaUserId);
    console.log('Final Meta Info - OrgScopedID:', metaOrgScopedId);
    console.log('Challenge Nonce:', nonce);

    if (message !== 'success') {
      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'meta rejected the attestation token.',
        16776960,
        [
          {
            name: 'Oculus Username',
            value: metaUsername || 'unknown',
            inline: true
          },
          {
            name: 'Oculus User ID',
            value: metaUserId || 'unknown',
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId || 'unknown',
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce || 'unknown',
            inline: true
          },
          {
            name: 'meta response',
            value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\``
          }
        ]
      );

      return res.status(401).json({ status: 'invalid', message: 'Attestation failed', meta: result });
    }
    
    const appState = claimsPayload.app_state || claimsPayload['https://graph.oculus.com/app_state'] || {};
    const deviceState = claimsPayload.device_state || claimsPayload['https://graph.oculus.com/device_state'] || {};

    // Check if security update is pending
    const securityUpdatePendingDays = deviceState?.security_update_pending_days;
    if (securityUpdatePendingDays !== undefined && securityUpdatePendingDays !== 0) {
      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'device has a pending security update.',
        16776960,
        [
          {
            name: 'Oculus Username',
            value: metaUsername || 'unknown',
            inline: true
          },
          {
            name: 'Oculus User ID',
            value: metaUserId || 'unknown',
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId || 'unknown',
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce || 'unknown',
            inline: true
          },
          {
            name: 'security_update_pending_days',
            value: securityUpdatePendingDays.toString(),
            inline: true
          }
        ]
      );

      return res.status(401).json({
        status: 'invalid',
        message: 'Device has pending security update',
        security_update_pending_days: securityUpdatePendingDays
      });
    }

    const certMatch = appState?.package_cert_sha256_digest?.some((cert) => cert.toLowerCase() === expectedCertHash.toLowerCase());

    if (appState?.app_integrity_state !== 'StoreRecognized' || appState?.package_id !== expectedPackageName || !certMatch || deviceState?.device_integrity_state !== 'Advanced') {
      let failedChecks = [];

      if (appState?.app_integrity_state !== 'StoreRecognized') {
        failedChecks.push(`app integrity state: ${appState?.app_integrity_state || 'missing'}`);
      }

      if (appState?.package_id !== expectedPackageName) {
        failedChecks.push(`package id: ${appState?.package_id || 'missing'}`);
      }

      if (!certMatch) {
        failedChecks.push('certificate hash did not match');
      }

      if (deviceState?.device_integrity_state !== 'Advanced') {
        failedChecks.push(`device integrity state: ${deviceState?.device_integrity_state || 'missing'}`);
      }

      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'the payload integrity checks failed.',
        16776960,
        [
          {
            name: 'Oculus Username',
            value: metaUsername || 'unknown',
            inline: true
          },
          {
            name: 'Oculus User ID',
            value: metaUserId || 'unknown',
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId || 'unknown',
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce || 'unknown',
            inline: true
          },
          {
            name: 'failed checks',
            value: failedChecks.length > 0
              ? failedChecks.join('\n')
              : 'unknown'
          },
          {
            name: 'app integrity state',
            value: appState?.app_integrity_state || 'missing',
            inline: true
          },
          {
            name: 'expected app state',
            value: 'StoreRecognized',
            inline: true
          },
          {
            name: 'package id',
            value: appState?.package_id || 'missing',
            inline: true
          },
          {
            name: 'expected package id',
            value: expectedPackageName,
            inline: true
          },
          {
            name: 'device integrity state',
            value: deviceState?.device_integrity_state || 'missing',
            inline: true
          },
          {
            name: 'expected device state',
            value: 'Advanced',
            inline: true
          },
          {
            name: 'certificate hashes',
            value: appState?.package_cert_sha256_digest?.length
              ? appState.package_cert_sha256_digest.join('\n').slice(0, 1000)
              : 'missing'
          },
          {
            name: 'expected certificate',
            value: expectedCertHash
          }
        ]
      );

      return res.status(401).json({
        status: 'invalid',
        message: 'payload integrity checks failed',
        claims: claimsPayload
      });
    }

    await sendWebhook(
      passedWebhook,
      'attestation passed',
      'the attestation was verified and all claims were accepted.',
      65280,
      [
        {
          name: 'Oculus Username',
          value: metaUsername || 'unknown',
          inline: true
        },
        {
          name: 'Oculus User ID',
          value: metaUserId || 'unknown',
          inline: true
        },
        {
          name: 'OrgScopedID',
          value: metaOrgScopedId || 'unknown',
          inline: true
        },
        {
          name: 'Challenge Nonce',
          value: nonce || 'unknown',
          inline: true
        },
        {
          name: 'app integrity state',
          value: appState?.app_integrity_state || 'missing',
          inline: true
        },
        {
          name: 'package id',
          value: appState?.package_id || 'missing',
          inline: true
        },
        {
          name: 'device integrity state',
          value: deviceState?.device_integrity_state || 'missing',
          inline: true
        },
        {
          name: 'certificate match',
          value: certMatch ? 'true' : 'false',
          inline: true
        },
        {
          name: 'security updates pending',
          value: securityUpdatePendingDays?.toString() || '0',
          inline: true
        },
        {
          name: 'device state',
          value: `\`\`\`json\n${JSON.stringify(deviceState, null, 2).slice(0, 1000)}\n\`\`\``
        },
        {
          name: 'app state',
          value: `\`\`\`json\n${JSON.stringify(appState, null, 2).slice(0, 1000)}\n\`\`\``
        }
      ]
    );

    return res.status(200).json({
      status: 'valid',
      message: 'Attestation verified and claims accepted',
      claims: claimsPayload,
      metaInfo: {
        username: metaUsername,
        userId: metaUserId,
        orgScopedId: metaOrgScopedId,
        challengeNonce: nonce
      }
    });

  } catch (error) {
    console.error('Error verifying token:', error);

    await sendWebhook(
      failedWebhook,
      'attestation failed',
      'the server encountered an error while verifying the attestation.',
      16776960,
      [
        {
          name: 'Oculus Username',
          value: 'unknown',
          inline: true
        },
        {
          name: 'Oculus User ID',
          value: 'unknown',
          inline: true
        },
        {
          name: 'OrgScopedID',
          value: 'unknown',
          inline: true
        },
        {
          name: 'Challenge Nonce',
          value: 'unknown',
          inline: true
        },
        {
          name: 'error',
          value: error.message || 'unknown error'
        }
      ]
    );

    return res.status(500).json({ status: 'error', message: 'Internal server error', error: error.message });
  }
});

app.get('/', (req, res) => {
  res.send('<body style="background-color: black; color: red;">ofc your here... yes this game has attestation.</body>');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
