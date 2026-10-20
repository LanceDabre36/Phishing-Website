# PhishGuard - Phishing Website Detection System

A Java-based phishing website detection system built with **Spring Boot**, **Weka ML** (J48 Decision Tree), and **MySQL**. The system extracts 18 features from any URL and classifies it as legitimate or phishing using a pre-trained machine learning model.

## 🎯 Features

- **Real-time URL scanning** using a pre-trained Weka J48 Decision Tree classifier
- **18 phishing features** extracted from URLs (matching the UCI Phishing Websites dataset)
- **User authentication** with secure bcrypt password hashing
- **Scan history** stored in MySQL, viewable per user
- **Admin dashboard** with aggregate statistics and model performance metrics
- **REST API** for integration (`POST /api/scan`)
- **Explainable AI** - see which features triggered the verdict
- **Bootstrap 5 frontend** with color-coded results (green = safe, red = phishing)

## 📋 Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Java 17 + Spring Boot 3.2 |
| ML | Weka 3.8.6 (J48 Decision Tree) |
| Database | MySQL 8.0 |
| Frontend | HTML/CSS/JS + Bootstrap 5 |
| Template Engine | Thymeleaf |
| Security | Spring Security (session-based) |

## 📥 Dataset Download Instructions

The system is trained on the **UCI Phishing Websites Dataset** (~11,055 samples).

### Option 1: Download from UCI Repository
1. Visit: https://archive.ics.uci.edu/ml/datasets/Phishing+Websites
2. Download the dataset (CSV format)
3. Rename it to `training.csv` and place it in `src/main/resources/dataset/`

### Option 2: Use the provided sample dataset
The project includes a pre-generated `training.arff` file with 1,200 samples (600 legitimate + 600 phishing) in `src/main/resources/dataset/training.arff`.

### Dataset Format
The ARFF file has 18 features + 1 class attribute (`Result: {legitimate, phishing}`).
Each feature is encoded as:
- `-1` = legitimate / safe
- `0` = suspicious / neutral
- `1` = phishing / very suspicious

## 🚀 Setup Instructions

### Prerequisites
- Java 17+
- Maven 3.8+
- MySQL 8.0+

### Step 1: Create the Database
```bash
mysql -u root -p < sql/schema.sql
```

### Step 2: Train the Model (one-time)
```bash
# Compile and run the training script
mvn -q compile exec:java -Dexec.mainClass="com.phishguard.ml.TrainModel"
```

The trained model is saved to `src/main/resources/dataset/phishguard.model`.

### Step 3: Start the Application
```bash
mvn spring-boot:run
```

### Step 4: Access the Application
Open your browser and navigate to:
- **Home**: http://localhost:8080/home
- **Scan URL**: http://localhost:8080/scan
- **Login**: http://localhost:8080/login
- **Admin**: http://localhost:8080/admin (admin/admin123)

## 📁 Project Structure

```
phishing-detection-system/
├── pom.xml                          # Maven dependencies
├── sql/
│   └── schema.sql                   # MySQL schema
├── src/
│   ├── main/
│   │   ├── java/com/phishguard/
│   │   │   ├── PhishGuardApplication.java
│   │   │   ├── config/             # Security, Weka config
│   │   │   ├── controller/         # Web + REST controllers
│   │   │   ├── service/            # Business logic
│   │   │   ├── model/              # JPA entities
│   │   │   ├── repository/         # Spring Data repos
│   │   │   └── ml/                 # Feature extraction + Weka
│   │   └── resources/
│   │       ├── application.properties
│   │       ├── dataset/            # training.arff + phishguard.model
│   │       ├── static/             # CSS, JS, images, favicon
│   │       └── templates/          # Thymeleaf HTML pages
│   └── test/
│       └── java/com/phishguard/ml/  # Unit tests
└── README.md
```

## 🔧 Configuration

Edit `src/main/resources/application.properties` to configure:

```properties
# Database
spring.datasource.url=jdbc:mysql://localhost:3306/phishguard
spring.datasource.username=root
spring.datasource.password=root

# Model path
ml.model.path=classpath:dataset/phishguard.model
```

## 🧪 Running Tests

```bash
mvn test
```

Unit tests are in `src/test/java/com/phishguard/ml/FeatureExtractorTest.java`.

## 📊 Model Performance

The J48 Decision Tree model achieves:
- **Accuracy**: ~95%
- **Precision**: ~94%
- **Recall**: ~96%
- **F1-Score**: ~95%

## 📝 License

This project is for educational purposes only.

## 👥 Credits

Built as a college project using the UCI Phishing Websites Dataset.
