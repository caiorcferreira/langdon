# LANGDON

LANGDON is LLM-powered detection engineering platform that helps security analysts to quickly and effectively author new rules.  

It uses your threat intelligence input, which is a combination by a threat report and your goal description, to generate a set of possible rules that can be used to detect the described threat.
You can tune it to use the log structure and follow the naming convention of your organization by providing examples.

The project is inspired by [DIANA](https://github.com/dwillowtree/diana).

## Run locally using Docker
1. Ensure you have Docker installed on your machine.
2. Build the Docker image:
    ```sh
    docker build -t langdon:latest .
    ```
3. Create a `.env` file in the root directory of the project using `.env.example` and replace the values.
4. Run the Docker container:
    ```sh
    docker run --rm -p 8081:8081 --env-file ./.env langdon:latest
    ```
5. Open your web browser and navigate to `http://localhost:8081` to access the application.

## Contributing
1. Fork the repository.
2. Clone your forked repository to your local machine:
    ```sh
    git clone https://github.com/caiorcferreira/langdon.git
    ```
3. Create a new branch for your feature or bugfix:
    ```sh
    git checkout -b feature-name
    ```
4. Make your changes and commit them with descriptive messages:
    ```sh
    git commit -m "Description of your changes"
    ```
5. Push your changes to your forked repository:
    ```sh
    git push origin feature-name
    ```
6. Open a pull request on the original repository and describe your changes.
