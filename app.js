import express from 'express';
import fs from 'fs/promises';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import https from 'https';
import crypto from 'crypto';

import { get_thumbprint, get_current_time, print_hex_binary, decrypt_response, create_transaction_id } from './include/utils.js';
import { create_signature } from './include/signature.js';
import { get_authorization } from './include/authorization.js';
import { symmetric_encrypt, asymmetric_encrypt } from './include/crypto.js';
import { base64_url_safe_string } from './include/base64.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "127.0.0.1";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// const allowedOrigins = ['https://example.com', 'https://another.com'];

// app.use(cors({
//   origin: function (origin, callback) {
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS')); 
//     }
//   },
//   credentials: true,
// }));

const individual_id_type_value = {
	'PCN': 'VID',
	'AlyasPSN': 'VID',
};

const otp_transactions = {};
const transaction_id_length = 10;

app.post('/request/otp/', async (req, res) => {
	console.log('---- OTP Request (Start) ----');
	try {
		const { individual_id, individual_id_type, otp_channel } = req.body;
		const transaction_id = `${create_transaction_id(transaction_id_length)}`;
		const misp_license_key = process.env.TSP_LICENSE_KEY;
		const partner_id = process.env.PARTNER_ID;
		const partner_api_key = process.env.API_KEY;
		const base_url = process.env.BASE_URL;

		let errors = [];

		if (!individual_id) {
			console.log("Error: Individual ID is required.");
			errors.push({ error: 'Individual ID is required' });
		}

		if (!individual_id_type) {
			console.log("Error: Individual ID Type is required.");
			errors.push({ error: 'Individual ID Type is required' });
		}

		if(!otp_channel) {
			console.log(`Error: OTP channel is required.`);
			errors.push({ error: 'OTP channel is required' });
		}
		
		if (errors.length > 0) {
			console.log('---- OTP Request (End) ----');
			return res.json(errors);
		}

		otp_transactions[individual_id] = transaction_id;

		const http_otp_request_body = {
			id: 'philsys.identity.otp',
			version: process.env.VERSION,
			transactionID: transaction_id,
			requestTime: get_current_time(),
			individualId: individual_id,
			individualIdType: individual_id_type_value[individual_id_type],
			otpChannel: otp_channel,
		};
	
		const partner_private_key_path = `./keys/${partner_id}/${partner_id}-partner-private-key.pem`;
		const http_otp_url = `${base_url}/idauthentication/v1/otp/${misp_license_key}/${partner_id}/${partner_api_key}`;
	
		const http_otp_request_header = {
			'signature': await create_signature(http_otp_request_body, partner_private_key_path),
			'authorization': await get_authorization(),
			'content-type': 'application/json',
		}

		console.log(`OTP URL: ${http_otp_url}\n`);
		console.log(`OTP Request Header: ${JSON.stringify(http_otp_request_header)}\n`);
		console.log(`OTP Request Body: ${JSON.stringify(http_otp_request_body)}\n`);
	
		const httpsAgent = new https.Agent({
			rejectUnauthorized: false 
		});

		const response = await fetch(http_otp_url, {
			method: 'POST',
			headers: http_otp_request_header,
			body: JSON.stringify(http_otp_request_body),
			agent: httpsAgent,
		});

		const otp_response = await response.json();

		let otp_result;
		if(response.ok && !otp_response['errors'] && !otp_response['error']) {
			otp_result = await decrypt_response(otp_response);	
		}
		else if(!response.ok) {
			otp_result = {
				error_code: response.status,
				error_message: response.statusText,
			};
		}
		else {
			otp_result = otp_response;
		}

		console.log('---- OTP Request (End) ----');
		return res.json(otp_result);
	}
	catch(error) {
		console.log(error);
		const otp_result = {
			error: 'An error occured. Please try again.'
		}

		console.log('---- OTP Request (End) ----');
		return res.json(otp_result);
	}
});

app.post('/authenticate', async (req, res) => {
	console.log('---- Authentication Request (Start) ----');
	try {
		const { individual_id, individual_id_type, is_ekyc, otp_value, demo_value, bio_value } = req.body;
		const request_time = get_current_time();	
		const transaction_id = !!otp_value ? otp_transactions[individual_id] : `${create_transaction_id(transaction_id_length)}`;
		const misp_license_key = process.env.TSP_LICENSE_KEY;
		const partner_id = process.env.PARTNER_ID;
		const partner_api_key = process.env.API_KEY;
		const base_url = process.env.BASE_URL;
	
		const ida_certificate_path = `./keys/${partner_id}/${partner_id}-IDAcertificate.cer`;
		const partner_private_key_path = `./keys/${partner_id}/${partner_id}-partner-private-key.pem`;
		const http_authentication_request_url = `${base_url}/idauthentication/v1/${is_ekyc ? 'kyc' : 'auth'}/${misp_license_key}/${partner_id}/${partner_api_key}`;
	
		let errors = [];

		if (!individual_id) {
			console.log(`Error: Individual ID is required.`);
        	errors.push({ error: 'Individual ID is required.' });
		}

		if (!individual_id_type) {
			console.log(`Error: Individual ID Type is required.`);
			errors.push({ error: 'Individual ID Type is required.' });
		}

		if (!otp_value && !demo_value && !bio_value) {
			console.log(`Error: Individual information is required.`);
			errors.push({ error: 'Individual information is required.' });
		}

		if(!!otp_value & !transaction_id) {
			console.log(`Error: OTP is required.`);
			errors.push({ error: 'OTP request is required.' });
		}

		if (errors.length > 0) {
			console.log('---- Authentication Request (End) ----');
			return res.json(errors);
		}
		
		if(!errors.length > 0 && !!otp_value) {
			delete otp_transactions[individual_id];
		}

		const http_authentication_request_body = {
			id: `philsys.identity.${is_ekyc ? 'kyc': 'auth'}`,
			version: process.env.VERSION,
			requestTime: request_time,
			env: process.env.ENV,
			domainUri: base_url,
			transactionID: transaction_id,
			requestedAuth: {
				otp: !!otp_value,
				demo: !!demo_value,
				bio: !!bio_value,
			},
			consentObtained: true,
			individualId: individual_id,
			individualIdType: individual_id_type_value[individual_id_type],
			request: {
				timestamp: request_time,
				otp: otp_value,
				demographics: demo_value,
				biometrics: bio_value,
			},
		};

		const http_authentication_request_body_request = http_authentication_request_body.request;

		const AES_SECRET_KEY = crypto.randomBytes(32);

		const ida_certificate = await fs.readFile(ida_certificate_path, 'utf8');

		http_authentication_request_body.request = base64_url_safe_string(symmetric_encrypt(AES_SECRET_KEY, JSON.stringify(http_authentication_request_body_request)));
		http_authentication_request_body.requestSessionKey = base64_url_safe_string(asymmetric_encrypt(ida_certificate, AES_SECRET_KEY));
		http_authentication_request_body.requestHMAC = base64_url_safe_string(symmetric_encrypt(AES_SECRET_KEY, print_hex_binary(JSON.stringify(http_authentication_request_body_request))));
		http_authentication_request_body.thumbprint = await get_thumbprint(ida_certificate_path);

		const http_authentication_request_header = {
			'signature': await create_signature(http_authentication_request_body, partner_private_key_path),
			'authorization': await get_authorization(),
			'content-type': 'application/json',
		}

		console.log(`Authentication URL: ${http_authentication_request_url}\n`);
		console.log(`Authentication Body: ${JSON.stringify(http_authentication_request_body)}\n`);
		console.log(`Authentication Body (Request): ${JSON.stringify(http_authentication_request_body_request)}\n`);

		const httpsAgent = new https.Agent({
			rejectUnauthorized: false
		});

		const response = await fetch(http_authentication_request_url, {
			method: 'POST',
			headers: http_authentication_request_header,
			body: JSON.stringify(http_authentication_request_body),
			agent: httpsAgent,
		});


		const authentication_response = await response.json();

		let authentication_result;

		if(response.ok && !authentication_response['error'] && !authentication_response['errors']) {
			authentication_result = await decrypt_response(authentication_response);	
		}
		else if(!response.ok) {
			authentication_result = {
				error_code: response.status,
				error_message: response.statusText,
			};
		}
		else {
			authentication_result = authentication_response;
		}

		console.log(`Authentication Response: ${JSON.stringify(authentication_result)}`);

		console.log('---- Authentication Request (End) ----');
		return res.json(authentication_result);
	}
	catch(error) {
		console.log(error);
		const authentication_result = {
			error: 'An error occured. Please try again.'
		}

		console.log('---- Authentication Request (End) ----');
		return res.json(authentication_result);
	}

});

app.listen(PORT, HOST, () => {
	console.log(`Server is running at http://${HOST}:${PORT}`);
});
