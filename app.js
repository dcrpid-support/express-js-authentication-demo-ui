import express from 'express';
import fs from 'fs/promises';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import https from 'https';
import crypto from 'crypto';

import { get_thumbprint, get_current_time, print_hex_binary, decrypt_response } from './include/utils.js';
import { create_signature } from './include/signature.js';
import { get_authorization } from './include/authorization.js';
import { symmetric_encrypt, asymmetric_encrypt } from './include/crypto.js';
import { base64_url_safe_string } from './include/base64.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

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

const individual_id_type = {
	'PCN': 'VID',
	'AlyasPSN': 'VID',
};

app.post('/request/otp/', async (req, res) => {
	console.log('---- OTP Request (Start) ----');
	try {
		const pcn = req.body.individual_id;
		const transaction_id = '1234567890';
		const misp_license_key = process.env.TSP_LICENSE_KEY;
		const partner_id = process.env.PARTNER_ID;
		const partner_api_key = process.env.API_KEY;
		const base_url = process.env.BASE_URL;
		let otp_channel = [];
		const otp_email = ['1', 'true', 't', 'yes', 'y', 'on'].includes(String(req.body.otp_email).toLowerCase());
		const otp_phone = ['1', 'true', 't', 'yes', 'y', 'on'].includes(String(req.body.otp_phone).toLowerCase());

		if(!otp_email && !otp_phone) {
			res.status(500).json({ error: 'OTP channel is required' });
		}

		if(otp_email) {
			otp_channel.push("email");
		}

		if(otp_phone) {
			otp_channel.push("phone");
		}
	
		const http_otp_request_body = {
			id: 'philsys.identity.otp',
			version: process.env.VERSION,
			transactionID: transaction_id,
			requestTime: get_current_time(),
			individualId: pcn,
			individualIdType: individual_id_type[req.body.individual_id_type],
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

		res.json(otp_result);
	}
	catch(error) {
		console.log(error);
		const otp_result = {
			error: 'An error occured. Please try again.'
		}

		res.json(otp_result);
	}

	console.log('---- OTP Request (End) ----');
});

app.post('/authenticate', async (req, res) => {
	try {
		const request = req.body;
		const request_time = get_current_time();
	
		const pcn = request.pcn;
		const transaction_id = '1234567890';
		const misp_license_key = process.env.TSP_LICENSE_KEY;
		const partner_id = process.env.PARTNER_ID;
		const partner_api_key = process.env.API_KEY;
		const base_url = process.env.BASE_URL;
		const is_ekyc = ['1', 'true', 't', 'yes', 'y', 'on'].includes(request.input_ekyc)
	
		const ida_certificate_path = `./keys/${partner_id}/${partner_id}-IDAcertificate.cer`;
		const partner_private_key_path = `./keys/${partner_id}/${partner_id}-partner-private-key.pem`;
		const http_authentication_request_url = `${base_url}/idauthentication/v1/${is_ekyc ? 'kyc' : 'auth'}/${misp_license_key}/${partner_id}/${partner_api_key}`;
	
		const http_authentication_request_body = {
			id: `philsys.identity.${is_ekyc ? 'kyc': 'auth'}`,
			version: process.env.VERSION,
			requestTime: request_time,
			env: process.env.ENV,
			domainUri: base_url,
			transactionID: transaction_id,
			requestedAuth: {
				otp: request.input_otp == 'on',
				demo: request.input_demo == 'on',
				bio: request.input_bio == 'on',
			},
			consentObtained: true,
			individualId: request.individual_id,
			individualIdType: individual_id_type[req.body.individual_id_type],
			request: {
				timestamp: request_time,
				otp: request.input_otp_value,
				demographics: JSON.parse(request.input_demo_value),
				biometrics: JSON.parse(request.input_bio_value),
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

		const httpsAgent = new https.Agent({
			rejectUnauthorized: false
		});

		const response = await fetch(http_authentication_request_url, {
			method: 'POST',
			headers: http_authentication_request_header,
			body: JSON.stringify(http_authentication_request_body),
			agent: httpsAgent,
		});

		console.log(`Authentication URL: ${http_authentication_request_url}\n`);
		// console.log(`Authentication Header: ${JSON.stringify(http_authentication_request_header)}\n`);
		console.log(`Authentication Body: ${JSON.stringify(http_authentication_request_body)}\n`);
		console.log(`Authentication Body (Request): ${JSON.stringify(http_authentication_request_body_request)}\n`);

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

		res.json(authentication_result);
	}
	catch(error) {
		console.log(error);
		const authentication_result = {
			error: 'An error occured. Please try again.'
		}

		res.json(authentication_result);
	}
});

app.listen(PORT, () => {
	console.log(`Server is running at http://localhost:${PORT}`);
});
