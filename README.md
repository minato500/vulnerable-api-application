# Vulnerable API Application

A deliberately vulnerable API application designed to learn about common API vulnerabilities in a safe environment

## Notes and Writeups

The notes and writeups are available at the [minato500.github.io](https://minato500.github.io/#posts/api-hacking/intro-to-api.md)

## Vulnerabilities Included

- BOLA (Broken Object Level Authorization)
- BFLA (Broken Function Level Authoriztion)
- Mass Assignment
- Brute Force Attack
- JWT Attacks
- SQL Injections
- NoSQL Injections
- Login Bypass
- Excessive Data Exposure
- SSRF (Server Side Request Forgery)
- Command Injection
- Vulnerability Chain

## Quick Start

### Prerequisites

- Docker
- Docker Compose

### Running the Application

```
# Clone the repository
git clone https://github.com/minato500/vulnerable-api-application.git
cd vulnerable-api-application

# Start the application
docker-compose up --build

# Access the application
open http://localhost:8090
```

### Stopping the Application

```
# stop the container by Ctl+c or
docker-compose down

# To remove all data
docker-compose down -v
```

### Important

Here in this lab we often change the privileges of the user so we should restart the container to old state 

```
docker-compose down -v && docker-compose up -d
```

> Note:
> In Brute Force attacks make sure the credentials given in application 
> To remove the data and restart the container `docker-compose down -v && docker-compose up -d`
