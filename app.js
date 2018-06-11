const ApiBuilder = require('claudia-api-builder');
const api = new ApiBuilder();
const AWS = require('aws-sdk');
const fetch = require('isomorphic-fetch');
const forgeSDK = require('forge-apis');

const getForgeSecrets = async () => {
	'use strict';
	let AWS = require('aws-sdk'),
    	endpoint = "https://secretsmanager.<your AWS region goes here>.amazonaws.com",
    	region = "<your AWS region goes here>",
    	secretName = "<your AWS secret store name goes here>",
    	secret,
		binarySecretData;
	let FORGE_CLIENT_ID, FORGE_CLIENT_SECRET;
	console.info('Creating a Secrets Manager client ...');
	const client = new AWS.SecretsManager({ endpoint: endpoint, region: region });
	return new Promise((resolve, reject) => {
		client.getSecretValue({SecretId: secretName}, (err, data) => {
			if(err) {
				if(err.code === 'ResourceNotFoundException') {
					console.error(`The requested secret ${secretName} was not found`);
				} else if(err.code === 'InvalidRequestException') {
					console.error(`The request was invalid due to: ${err.message}`);
				} else if(err.code === 'InvalidParameterException') {
					console.error(`The request had invalid params: ${err.message}`);
				}
				reject(err);
			} else {
				// Decrypted secret using the associated KMS CMK
				// Depending on whether the secret was a string or binary, one of these fields will be populated
				if(data.SecretString !== "") {
					secret = data.SecretString;
					const secret_json = JSON.parse(secret);
					if (Object.keys(secret_json).length === 1) {
						FORGE_CLIENT_ID = Object.keys(secret_json)[0];
						FORGE_CLIENT_SECRET = Object.values(secret_json)[0];
						const appSecrets = { 
							ForgeClientID: FORGE_CLIENT_ID,
							ForgeClientSecret: FORGE_CLIENT_SECRET
						};
						console.info('Successfully retrieved the app secrets!');
						resolve(appSecrets);
					}
				} else {
					binarySecretData = data.SecretBinary;
					console.error('Unexpected binary data in secrets!');
					reject(Error('Unexpected binary data in secrets!'));
				}
			}
		});
	});
};

const getForgeToken = async (secrets) => {
	'use strict';
	const forgeSDK = require('forge-apis');
	return new Promise((resolve, reject) => {
		// Initialize the 2-legged oAuth2 Forge client
		const oAuth2TwoLegged = new forgeSDK.AuthClientTwoLegged(secrets['ForgeClientID'], secrets['ForgeClientSecret'], ['data:read', 'bucket:read'], true);
		oAuth2TwoLegged.authenticate()
			.then(function(credentials){
				console.info('Successfully authenticated to the Forge app!');
				resolve(credentials);
			}, function(err) {
				console.error(`Error retrieving credentials: ${JSON.stringify(err)}.`);
				reject(JSON.stringify(err));
		});
	});
};

const setForgeTokenInDb = async (credentials) => {
	'use strict';
	const AWS = require('aws-sdk');
	AWS.config.update({ region: 'us-east-1' });
	const ddb = new AWS.DynamoDB({ apiVersion: '2012-10-08' });
	const params = {
		TableName: 'ForgeAuthSession',
		Item: {
			'AccessToken': { S: credentials.access_token },
			'ExpiresAt': { S: credentials.expires_at.toString() }
		}
	}
	return new Promise((resolve, reject) => {
		ddb.putItem(params, function(err, data) {
			if(err) {
				console.error(JSON.stringify(err));
				reject(err);
			} else {
				console.info(`Successfully inserted ${JSON.stringify(params.Item)} in database!`);
				resolve('success');
			}
		});
	});
};

const deleteTokenInDb = async (access_token, expires_at) => {
    const params = {
        Key: {
            AccessToken: {
                S: access_token.replace('Bearer ', '')
            }, 
            ExpiresAt: {
                S: expires_at
            }
        },
        TableName: 'ForgeAuthSession'
    };
    const ddb = new AWS.DynamoDB({ apiVersion: '2012-10-08' });
    return new Promise((resolve, reject) => {
        ddb.deleteItem(params, function(err, data) { // truncate the table
            if (err) {
                console.error(err);
                reject(err);
            } else {
                console.info(`Successfully deleted item from DynamoDB!`);    
                resolve(data);        
            }
        });
    });
};

module.exports = api;

api.registerAuthorizer('forge-authorize', {
    lambdaName: 'forgeAuthorize',
    lambdaVersion: true
});

api.get('/', function() {
    'use strict';
    const html = `<html>
        <body>
        <h1>Welcome to the forge-get-hubs main page</h1>
        To access the hubs browse to <b>/hubs</b> resource path.
        You will need to specify an Authorization header and use GET verb.
        </body>
    </html>`;
    return html;
}, { success: { contentType: 'text/html' } });

api.get('/hubs', async = (request) => {
    'use strict';
    if(!request.context.authorizer.authToken) {
        return 'Failed to find bearer token value!';
    }
    return fetch('https://developer.api.autodesk.com/project/v1/hubs', {
        method: 'GET',
        headers: { Authorization: request.context.authorizer.authToken }
    })
        .then( async (res) => {
            const delToken = await deleteTokenInDb(request.context.authorizer.authToken, request.context.authorizer.expiresAt);
            console.info(`GET Hubs response: ${JSON.stringify(res)}`);
            if (res.ok) {
                return res.json();
            } else if (res.status === 401) {
                console.error('401 - Unauthorized.');
                const secrets = await getForgeSecrets();
                const credentials = await getForgeToken(secrets);
                const dbInfo = await setForgeTokenInDb(credentials);
	            if(dbInfo === 'success') {
		            console.info('Successfully stored new Forge credentials in database!');
	            } else {
		            console.error('Failed to store new Forge auth credentials in database!');
	            }
                return '401 - Unauthorized';
            } else {
                console.error('Failed to get hubs!');
                return 'Failed to get hubs!';
            }
        })
        .catch( (err) => {
            console.error(`Failed to get hubs: ${JSON.stringify(err)}`);
        });
}, { customAuthorizer: 'forge-authorize' });
