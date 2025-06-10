# Student Management System (SMS) - A Microservices-Based Application

This project is a boilerplate Student Management System (SMS) built with a microservices architecture. It serves as a
practical example for understanding and implementing REST API concepts. The system provides functionalities for managing
students, professors, courses, and enrollments, with robust authentication and role-based access control. Also it is
part of the college assignment submission for Software Architecture and Development module.

## Features

* User authentication (students and professors)
* Role-based access control (Admin, Professor, Student)
* Student, Professor, Course, and Enrollment management (CRUD operations)
* Secure JWT-based authentication with JWKS for public key distribution

## API Documentation

The API documentation can be found on Postman:
[Postman API Documentation](https://www.postman.com/giripriyadarshan/srh-de/overview)

## Architecture

The project follows a microservices architecture, where different functionalities are handled by independent services.
This promotes modularity, scalability, and maintainability.

The services are:

* **Auth Service:** Handles user authentication (login, registration) and JWT generation. It validates credentials and
  issues tokens for accessing other services.
* **Student Service:** Manages all student-related data. This includes creating, reading, updating, and deleting student
  records (CRUD operations).
* **Professor Service:** Manages all professor-related data, including CRUD operations for professor records.
* **Course Service:** Manages course information, such as course creation, updates, and listing available courses (CRUD
  operations).
* **Enrollment Service:** Manages student enrollments in courses. It handles the process of students enrolling in
  courses and tracks enrollment status.

## Getting Started

Follow these instructions to get the project up and running on your local machine.

### Prerequisites

Ensure you have the following software installed:

* Node.js (LTS version recommended)
* npm (Node Package Manager, typically comes with Node.js)
* MongoDB (Make sure your MongoDB server is running)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/giripriyadarshan/software_architecture_and_development_classwork.git
   ```
2. Navigate to the project directory:
   ```bash
   cd software_architecture_and_development_classwork/SMS-Template
   ```
3. Install dependencies for each service. Open separate terminal windows or tabs for each service.

    * **Auth Service:**
      ```bash
      cd authService
      npm install
      cd ..
      ```
    * **Course Service:**
      ```bash
      cd courseService
      npm install
      cd ..
      ```
    * **Enrollment Service:**
      ```bash
      cd enrollmentService
      npm install
      cd ..
      ```
    * **Professor Service:**
      ```bash
      cd professorService
      npm install
      cd ..
      ```
    * **Student Service:**
      ```bash
      cd studentService
      npm install
      cd ..
      ```
   *Alternatively, you can run the installation commands sequentially from the `SMS-Template` root directory as per the
   original issue:*
   ```bash
   # From SMS-Template directory
   cd authService && npm install
   cd ../courseService && npm install
   cd ../enrollmentService && npm install
   cd ../professorService && npm install
   cd ../studentService && npm install
   # Navigate back to SMS-Template if needed
   cd .. 
   ```

### Running the Application

To run all services concurrently from the `SMS-Template` directory, use the following command:

```bash
npm run start:all
```

This will start each microservice. Make sure MongoDB is running before starting the services.

### Environment Variables

Each service requires a `.env` file in its respective directory (e.g., `SMS-Template/authService/.env`). These files
contain essential configuration variables.

Create a `.env` file for each service based on the examples below.

**Example `.env` structure for most services (Student, Professor, Course, Enrollment):**

```env
PORT=XXXX # e.g., PORT=3001 for Student Service
MONGO_URI=mongodb://localhost:27017/your_sms_db_name # Replace with your MongoDB connection string and database name
# Add any other service-specific variables if needed
```

**Example `.env` structure for Auth Service:**

```env
PORT=XXXX # e.g., PORT=3000
MONGO_URI=mongodb://localhost:27017/your_sms_db_name # Replace with your MongoDB connection string and database name
```

**Important:**

* Replace `XXXX` with the desired port number for each service. Ensure each service runs on a different port.
* Replace `your_sms_db_name` with your actual database name.
* It's recommended to use a centralized configuration management system for production environments instead of
  individual `.env` files.

## Built With

* **Node.js:** JavaScript runtime environment.
* **Express.js:** Web application framework for Node.js.
* **MongoDB:** NoSQL database for storing application data.
* **Mongoose:** ODM (Object Data Modeling) library for MongoDB and Node.js.
* **JSON Web Tokens (JWT):** For creating access tokens for secure authentication.
* **Bcrypt.js:** Library for hashing passwords.
