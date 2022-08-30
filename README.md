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

## The MCP Trust Store
The authentication in our current MCP test-bed is based on a stand-alone 
Keycloak server. To run that in production mode we need an SSL certificate and
to simplify things, a self-signed one was generated. This however causes some
issues with the connection validation through Eureka. To avoid the issues
with a non-recognised certificate a trust-store that contains this certificate
has been included in the service. The trust-store was generated using the 
following command:

    keytool -import -file keycloak-selfsigned.crt -alias keycloak_selfsigned -keystore mcpTrustStore

After adding the generated trust-store into the resources of the service, the
keycloak configuration was updated to pick it up:

    keycloak.truststore=classpath:mcpTrustStore
    keycloak.truststore-password=<trust-store-password>

One more thing to be sorted is the keycloak admin operation, that also requieres
knowledge of the accepted certificate. To deal with this, the certificate is
loaded as a resource and passed on to a RESTEasy client, utilised by the
Keycloak admin library.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to
discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
Distributed under the Apache License. See [LICENSE](./LICENSE) for more
information.

## Contact
Nikolaos Vastardis - Nikolaos.Vastardis@gla-rad.org

