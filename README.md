# LANGDON



## Run locally Using Docker
1. Ensure you have Docker installed on your machine.
2. Build the Docker image:
    ```sh
    docker build -t langdon:latest .
    ```
4. Create a `.env` file in the root directory of the project using `.env.example` and replace the values.
3. Run the Docker container:
    ```sh
    docker run --rm -p 8081:8081 --env-file ./.env langdon:latest
    ```
4. Open your web browser and navigate to `http://localhost:8081` to access the application.

## Contributing
1. Fork the repository.
2. Clone your forked repository to your local machine:
    ```sh
    git clone https://github.com/your-username/langdon.git
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
6. Open a merge request on the original repository and describe your changes.
