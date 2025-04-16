# FB-AutoShare

FB-AutoShare is a Python-based project designed to automate the sharing of posts on Facebook. This tool simplifies the process of sharing content, making it easier to maintain an active presence on the platform.

## Features

- Automates the sharing of posts on Facebook.
- Supports scheduling and customization options.
- Easy-to-use and configurable interface.
- Built using Python and HTML for seamless interaction and performance.

## Language Composition

- **Python:** 65.8%
- **HTML:** 34.2%

## Prerequisites

Before using this project, ensure you have the following installed:

- Python 3.7 or higher
- Pip (Python package manager)
- A Facebook account for testing purposes (ensure compliance with Facebook's policies)

## Installation

Follow these steps to set up the project:

1. Clone the repository:
   ```bash
   git clone https://github.com/gpbot-org/FB-AutoShare.git
   cd FB-AutoShare
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
## On Render 
1. At first login via github account on render 
2. fork this repo
3. on render added this repo to  web service
4. on start command add `python Auto.py`
5. select free or paid option and deploy

## Usage

1. Configure the project settings:
   - Update the necessary configuration files to include your Facebook credentials and desired settings.

2. Run the script:
   ```bash
   python main.py
   ```

3. Follow the instructions provided in the terminal to share posts automatically.

## Build Details

- **Build Tool:** No external build tool is required. The project runs as a Python script.
- **Dependencies:** All dependencies are listed in the `requirements.txt` file.
- **Setup Command:** Use `pip install -r requirements.txt` to install dependencies.
- **Run Command:** Use `python main.py` to execute the project.

## Contributing

We welcome contributions! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request on the main repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool must be used in compliance with Facebook's terms of service. Automating actions on Facebook may lead to account restrictions or bans. Use this tool responsibly.
