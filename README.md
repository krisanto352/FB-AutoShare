# GRANDPA FB Share Tool

A web application for automating Facebook post sharing with anti-spam protection.

## Features

- Web interface for Facebook post sharing
- Configurable delay settings to avoid spam protection
- Retry mechanism with progressively longer delays
- Token validation and error handling
- Multiple sharing methods to bypass rate limits
- Session management for storing credentials
- Modern, digital-style UI with green and blue colors

## Installation

1. Clone the repository:
```
git clone https://github.com/gpbot-org/FB-AutoShare.git
cd FB-AutoShare
```

2. Create a virtual environment:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Set up environment variables:
```
cp .env.example .env
```
Edit the `.env` file to set your secret key.

5. Run the application:
```
flask run
```

6. Open your browser and navigate to:
```
http://127.0.0.1:5000
```



## ⚠️ Get Token and Cookie ⚠️

To obtain your Facebook cookies and access token, you can use the [Get Token Cookie](https://chromewebstore.google.com/detail/get-token-cookie/naciaagbkifhpnoodlkhbejjldaiffcm) Chrome extension. Follow the instructions provided in the extension to retrieve the necessary credentials.


## Usage

1. Log in with your Facebook cookies and access token
2. Enter the post link you want to share
3. Set the number of times to share
4. Configure delay settings to avoid being blocked
5. Start sharing!

## Configuration

You can configure the following settings:

- **Share Delay**: Time to wait between each share (seconds)
- **Retry Delay**: Time to wait before retrying after an error (seconds)
- **Max Retries**: Maximum number of retry attempts per share

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes only. Use at your own risk. The developers are not responsible for any account restrictions or bans resulting from the use of this tool.
