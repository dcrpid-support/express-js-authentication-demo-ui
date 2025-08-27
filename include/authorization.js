import fetch from 'node-fetch';
import dotenv from 'dotenv';
import https from 'https';
import { get_current_time } from './utils.js';

dotenv.config();

export const get_authorization = async () => {
    try {
        const http_authorization_request_body = {
            requestTime: get_current_time(),
            request: {
                clientId: process.env.CLIENT_ID,
                secretKey: process.env.SECRET_KEY,
                appId: process.env.APP_ID,
            },
        }
    
        const http_authorization_request_header = {
            "content-type": "application/json",
        }

        const http_authorization_url = `${process.env.BASE_URL}/v1/authmanager/authenticate/clientidsecretkey`;

        const httpsAgent = new https.Agent({
           rejectUnauthorized: false 
        });

        // console.log(`Authorization URL: ${http_authorization_url}`);

        const response = await fetch(http_authorization_url, {
            method: 'POST',
            headers: http_authorization_request_header,
            body: JSON.stringify(http_authorization_request_body),
            agent: httpsAgent,
        });

        // console.log(`Authorization Token URL status: ${response.status}`);

        const authorization_token = response.headers.get('authorization');

        return authorization_token;
    }
    catch (error) {
        console.log(error);
    }
}