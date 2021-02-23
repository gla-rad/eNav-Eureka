# e-Navigation Eureka Server
The eureka repository contains the implementation of a simple service discovery
micro-service based on the well-known Sprintboot/Netflix eureka server.

## Development Setup
To start developing just open the repository with the IDE of your choice. The 
original code has been generated using 
[Intellij IDEA](https://www.jetbrains.com/idea). Just open it by going to:
    
    File -> New -> Project From Verson Control

Provide the URL of the current repository and the local directory you want. 

You don't have to use it if you have another preference. Just make sure you 
update the *.gitignore* file appropriately.

## Build Setup
The project is using the latest OpenJDK 11 to build, although earlier versions
should also work.

To build the project you will need Maven, which usually comes along-side the 
IDE. Nothing exotic about the goals, just clean and install should do:

    mvn clean package

## Configuration
The configuration of the eureka server is based on the properties files found
in the *main/resources* directory.

The *boostrap.properties* contains the necessary properties to start the service
while the *application.properties* everything else i.e. the security 
configuration.

At some point we do intent to use this service as also a configuration server
that will provide the configuration to all other micro-services of our 
e-Navigation suite.

## Running the Service
To run the service, just like any other Springboot micro-service, all you need
to do is run the main class, i.e. MessageBroker. No further arguments are
required. Everything should be picked up through the properties files.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to
discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
Distributed under the Apache License. See [LICENSE](./LICENSE) for more
information.

## Contact
Nikolaos Vastardis - Nikolaos.Vastardis@gla-rad.org

