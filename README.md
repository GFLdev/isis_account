# ISIS Account Microservice

![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

## Overview

The **ISIS Account** microservice is responsible for managing user identities, group-based access control,
authentication, refresh tokens and audit logging. It is a core component in the modular ISIS system.

## Features

- JWT-based authentication with refresh token support.
- User account creation, update, deactivation and deletion. **(Not implemented)**
- Group-based access control (RBAC). **(Not implemented)**
- Login attempts tracking with IP and User-Agent logging. **(In progress)**
- Refresh token issuance and expiration control.
- Structured audit logging for account-related actions. **(Not implemented)**

## Requirements

To use or contribute to this project, ensure the following packages are installed on your system:

- **Go 1.24+**
- **PostgreSQL**
- **Docker** (for containerized deployment)

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/GFLdev/isis_account
cd isis_account
```

### 2. Build the Docker image

```bash
docker build -t isis-account-service .
```

### 3. Run the container

```bash
docker run isis-account-service
```

## Documentation

Full OpenAPI (Swagger) documentation will be available under `/docs/swagger/index.html`.
**(Not implemented)**

### Contribution

Contributions are welcome! Follow these steps to make a contribution:

- Fork the repository.
- Create a new branch: git checkout -b feature-name.
- Commit your changes: git commit -m "Add feature-name".
- Push to the branch: git push origin feature-name.
- Create a Pull Request.

## License

This project is licensed under [MIT](./LICENSE). See the LICENSE file for more details.

## Contact

For questions or support, feel free to contact the development team at [gabriel.franco@gfldev.com](mailto:gabriel.franco@gfldev.com]).

