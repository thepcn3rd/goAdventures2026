# Object Analyzer

Object Analyzer is a distributed Go-based application designed to process and analyze data objects asynchronously. It utilizes a producer-consumer architecture where a central API server manages requests and specialized "Worker Bees" perform the heavy lifting of data analysis.

## Project Structure

```
objectAnalyzer/
├── apiServer/          # The entry point for the application
│   └── main.go         # API routing and server initialization
├── workerBee/          # The processing engine (Consumer)
│   ├── main.go         # Worker initialization and task polling
│   └── processor/      # Analysis logic and object inspection
├── common/             # Shared data models and utilities
|   └── common.go       # Common functions used
|   └── commonCreateCerts.go 
|   └── handlers.go     # Handles processing for all components
├── data/               # Location of the database used 
├── connectors/         (Future) Pre-built connectors to ingest data
├── adminClient/        (Future) Admin Client
```


![HikingAdams](/picts/hikingAdams.png)
## Components

### 1. apiServer

The **apiServer** acts as the gateway to the system. It exposes a RESTful API that allows users or external systems to submit objects for analysis.

- **Responsibility**: Receives incoming JSON payloads, validates them, and persists them into a task queue or database.
    
- **Workflow**: When a request is received, the `apiServer` generates a unique `TaskID`, acknowledges the request immediately (returning the ID to the user), and hands the task off to the messaging layer.
    
- **Key Features**:
    
    - HTTP Endpoint management.
        
    - Input validation.
        
    - Status tracking (allowing users to query the state of a specific analysis).
        

### 2. workerBee

The **workerBee** is the background processing service. It is designed to be horizontally scalable, meaning you can run multiple instances of the worker to handle high volumes of data.

- **Responsibility**: It "polls" or subscribes to the task queue populated by the `apiServer`. Once it picks up a task, it performs the actual object analysis.
    
- **Workflow**: It de-serializes the object data, runs specific analysis algorithms (defined in the `processor/` package), and updates the final result in the shared data store.
    
- **Key Features**:
    
    - Asynchronous execution.
        
    - Error handling and retry logic.
        
    - Resource-intensive task isolation (keeping the API fast by offloading work).
        

## Getting Started

### Prerequisites

- Go 1.21+
    
- A running instance of the required message broker (e.g., Redis or RabbitMQ) as defined in your environment config.
    

### Running the API Server

Create a go.work in the respective directory to use the common directory.
```
go 1.25.5

use (
	.
	../common
)
```

Create a go.mod file in the common directory... Run prep.sh and it should generate a go.mod file similar to the below
```
module common

go 1.25.5

require github.com/mattn/go-sqlite3 v1.14.33 // indirect
```

Create and run the binary for the apiServer
```
cd apiServer
./prep.sh
./apiServer
```

### Running the Worker Bee

Create and run the binary for the Worker Bee
```
cd workerBee
./prep.sh
./workerBee
```

