# e-Navigation Eureka Server
The eureka repository contains the implementation of a simple service discovery
micro-service based on the well-known Sprintboot/Netflix eureka server.

## Development Setup
To start developing just open the repository with the IDE of your choice. The 
original code has been generated using 
[Intellij IDEA](https://www.jetbrains.com/idea). Just open it by going to:
    
    File -> New -> Project From Version Control

Provide the URL of the current repository and the local directory you want. 

You don't have to use it if you have another preference. Just make sure you 
update the *.gitignore* file appropriately.

## Build Setup
The project is using the latest OpenJDK 21 to build, although earlier versions
should also work.

To build the project you will need Maven, which usually comes along-side the 
IDE. Nothing exotic about the goals, just clean and install should do:

    mvn clean package

## Configuration
This service provide the eureka server for the GLA e-Navigation Service
Architecture, but it also supports a configuration server that makes the
configuration properties stored in an online repository (e.g. through Git)
available to the architecture services.

The basic configuration of the eureka server is based on the 
*bootstrap.properties* files found the *main/resources* directory. This 
contains the necessary properties to start the service and connect to the
specified cloud config repository so that it can retrieve the remaining
*application.properties* files for everything else i.e. the security 
configuration.

## Running the Service
To run the service, just like any other Springboot micro-service, all you need
to do is run the main class, i.e. Eureka. No further arguments are
required. Everything should be picked up through the properties files.

## The MCP Trust Store
The authentication in our current e-Navigation Service Architecture test-bed is
based on a stand-alone  Keycloak server. To run that in testing/production mode
we need an MCP SSL certificate which up to this point is a self-signed one.
This however causes some issues with the connection validation through Eureka. To
avoid the issues with a non-recognised certificate a trust-store that contains
this certificate has been included in the service. The trust-store was generated
using the following command:

    keytool -import -trustcacerts -noprompt -alias mcp-root -file mcp-root-cert.cer -keystore truststore.p12
    keytool -import -trustcacerts -noprompt -alias mcp-idreg -file mcp-idreg-cert.cer -keystore truststore.p12

After adding the generated trust-store into the resources of the service, the
configuration must be updated to pick it up:

    server.ssl.trust-store=classpath:truststore.jks
    server.ssl.trust-store-password=<trust-store-password>

One more thing to be sorted is the keycloak admin operation, that also requires
knowledge of the accepted certificate. To deal with this, the certificate is
loaded as a resource and passed on to a RESTEasy client, utilised by the
Keycloak admin library.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to
discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
Distributed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for
more information.

## Contact
Nikolaos Vastardis - Nikolaos.Vastardis@gla-rad.org

