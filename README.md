
# Traefik Dynamic Logger

This project provides a dynamic logging solution for Traefik, a popular reverse proxy and load balancer. The logger enables flexible log management and integration with Traefik's dynamic configuration features.

## Features
- Dynamic log level adjustment
- Integration with Traefik middleware
- Customizable log output formats
- Easy configuration via environment variables or files

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/traefik_dynamic_logger.git
   ```
2. Build the project:
   ```bash
   go build -o traefik_dynamic_logger
   ```

## Usage
- Configure Traefik to use the logger as a middleware.
- Adjust log levels and formats as needed in the configuration file or environment variables.
- Start the logger service:
   ```bash
   ./traefik_dynamic_logger
   ```

## Configuration
- Environment variables:
  - `LOG_LEVEL`: Set the log level (e.g., info, debug, warn, error)
  - `LOG_FORMAT`: Set the log format (e.g., json, text)
- Configuration file example:
  ```yaml
  log:
    level: info
    format: json
  ```

## Contributing
Contributions are welcome! Please open issues or submit pull requests for improvements or bug fixes.

## License
This project is licensed under the MIT License.
>>>>>>> a633511 (Add dynamic security logger middleware and update README)
