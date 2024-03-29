# The GLA e-Navigation Service Architecture - Eureka Service

The Eureka repository contains the implementation of a simple service discovery
microservice for the GRAD e-Navigation Service Architecture, based on the
well-known Springboot/Netflix eureka server.

## What is e-Navigation

The maritime domain is facing a number for challenges, mainly due to the
increasing demand, that may increase the risk of an accident or loss of life.
These challenges require technological solutions and e-Navigation is one such
solution. The International Maritime Organization ([IMO](https://www.imo.org/))
adopted a ‘Strategy for the development and implementation of e‐Navigation’
(MSC85/26, Annexes 20 and 21), providing the following definition of
e‐Navigation:

<div style="padding: 4px;
    background:lightgreen;
    border:2px;
    border-style:solid;
    border-radius:20px;
    color:black">
E-Navigation, as defined by the IMO, is the harmonised collection, integration,
exchange, presentation and analysis of maritime information on-board and ashore
by electronic means to enhance berth-to-berth navigation and related services,
for safety and security at sea and protection of the marine environment.
</div>

In response, the International Association of Lighthouse Authorities
([IALA](https://www.iala-aism.org/)) published a number of guidelines such as
[G1113](https://www.iala-aism.org/product/g1113/) and
[G1114](https://www.iala-aism.org/product/g1114/), which establish the relevant
principles for the design and implementation of harmonised shore-based technical
system architectures and propose a set of best practices to be followed. In
these, the terms Common Shore‐Based System (CSS) and Common Shore‐based System
Architecture (CSSA) were introduced to describe the shore‐based technical system
of the IMO’s overarching architecture.

To ensure the secure communication between ship and CSSA, the International
Electrotechnical Commission (IEC), in coordination with IALA, compiled a set of
system architecture and operational requirements for e-Navigation into a
standard better known as [SECOM](https://webstore.iec.ch/publication/64543).
This provides mechanisms for secure data exchange, as well as a TS interface
design that is in accordance with the service guidelines and templates defined
by IALA. Although SECOM is just a conceptual standard, the Maritime Connectivity
Platform ([MCP](https://maritimeconnectivity.net/)) provides an actual
implementation of a decentralised framework that supports SECOM.

## What is the GRAD e-Navigation Service Architecture

The GLA follow the developments on e-Navigation closely, contributing through
their role as an IALA member whenever possible. As part of their efforts, a
prototype GLA e-Navigation Service Architecture is being developed by the GLA
Research and Development Directorate (GRAD), to be used as the basis for the
provision of the future GLA e-Navigation services.

As a concept, the CSSA is based on the Service Oriented Architecture (SOA). A
pure-SOA approach however was found to be a bit cumbersome for the GLA
operations, as it usually requires the entire IT landscape being compatible,
resulting in high investment costs. In the context of e-Navigation, this could
become a serious problem, since different components of the system are designed
by independent teams/manufacturers. Instead, a more flexible microservice
architecture was opted for. This is based on a break-down of the larger
functional blocks into small independent services, each responsible for
performing its own orchestration, maintaining its own data and communicating
through lightweight mechanisms such as HTTP/HTTPS. It should be pointed out that
SOA and the microservice architecture are not necessarily that different.
Sometimes, microservices are even considered as an extension or a more
fine-grained version of SOA.

## The e-Navigation Eureka Service

This is the internal component the handles the service discovery and facilitates
the microservice inter-communication. It should not be confused with a MCP MSR
component, as it is only focused on the discoverability of the internal
e-Navigation Service Architecture microservices. It is based on the
[Netflix Eureka](https://github.com/Netflix/eureka) service implementation which
allows the registered microservices to be contacted via a simple name identifier.
It removes the requirement for microservices to be aware of each other’s
addresses (IP, URL) beforehand, and also supports the system scaling operation
by allowing multiple instances of each microservice to be used according to a
selected load-balancing strategy.

The current implementation is also enriched with additional functionality that
supports a
[Springboot Admin](http://docs.spring-boot-admin.com/current/index.html)
server for monitoring, as well as a
[Spring Cloud Config](https://spring.io/projects/spring-cloud-config) server
that provides support for externalized configuration in a distributed system.

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

## How to Run

This service can be used in two ways (based on the use or not of the Spring Cloud
Config server).
* Enabling the cloud config server and distributing the configurations located
  in an online repository.
* Disabling the cloud config server and using the configuration provided
  locally.

### Cloud Config Configuration

In order to run the service in a **Cloud Config** configuration, you just need
to provide the environment variables that allow it to connect to the online
configuration repository. This is assumed to be provided through a VCS system
like [Git](https://git-scm.com/downloads).

The available environment variables are:

    ENAV_CONFIG_ENCRYPTION_KEY=<encryption key>;
    ENAV_CONFIG_REPO_URL=<The online location of the Git configuration repo>
    ENAV_CONFIG_REPO_BRANCH=<branch of the Git configuration repo
    ENAV_CONFIG_REPO_USERNAME=<Git configuration repo username>
    ENAV_CONFIG_REPO_PASSWORD=<Git configuration repo password>

The variables will be picked up and used to populate the default
**bootstrap.properties** of the service that looks as follows:

    server.port=8761
    spring.application.name=eureka
    spring.application.version=<application.version>
    
    # The Spring Cloud Server Config
    spring.cloud.config.server.bootstrap=true
    spring.cloud.config.server.git.clone-on-start=true
    spring.cloud.config.server.prefix=config
    spring.cloud.config.server.git.uri=${ENAV_CONFIG_REPO_URL}
    spring.cloud.config.server.git.username=${ENAV_CONFIG_REPO_USERNAME}
    spring.cloud.config.server.git.password=${ENAV_CONFIG_REPO_PASSWORD}
    spring.cloud.config.server.git.default-label=${ENAV_CONFIG_REPO_BRANCH}

    # The Spring Cloud Client Config
    spring.cloud.config.username=${ENAV_CLOUD_CONFIG_USERNAME}
    spring.cloud.config.password=${ENAV_CLOUD_CONFIG_PASSWORD}

    # Enable parameter encryption
    encrypt.key=${ENAV_CONFIG_ENCRYPTION_KEY}

As you can see, the service is called **eureka** and uses the **8761** port when
running. Also, the configuration and the encryption/decryption functionality is
available under the **/config/**  path. Basic authentication is used just for
this path, so make sure this is not made publicly available as security concerns
are involved.

To run the image, along with the aforementioned environment variables, you can
use the following command:

    java -jar \
        -DENAV_CONFIG_REPO_URL='<git repository url>' \
        -DENAV_CONFIG_REPO_BRANCH='<git repository branch>' \
        -DENAV_CONFIG_REPO_USERNAME='<git repository username>' \
        -DENAV_CONFIG_REPO_PASSWORD='<git repository passord>' \
        -DENAV_CONFIG_ENCRYPTION_KEY='<key to be used for param encryption/decryption>' \
        -DENAV_CLOUD_CONFIG_USERNAME='<username for clients to access the config>' \
        -DENAV_CLOUD_CONFIG_PASSOWRD='<password for clients to access the config>' \
        <eureka.jar>

### Local Config Configuration

In order to run the service in a **Local Config** configuration, you just need
to provide a local configuration directory that contains the necessary
**.properties** files (including bootstrap).

Then we can run the service in the following way:

    java -jar \
        --spring.config.location=optional:classpath:/,optional:file:<config_dir>/ \
        <eureka.jar>

Examples of the required properties files can be seen below.

For bootstrapping, we need to disable the cloud config server, and clear out the
environment variable inputs:

    server.port=8761
    spring.application.name=eureka
    
    # Disable the cloud config server
    spring.cloud.config.enabled=false
    spring.cloud.config.server.enabled=false
    spring.cloud.config.server.bootstrap=false
    
    # Clear out the environment variables
    spring.cloud.config.server.git.uri=
    spring.cloud.config.server.git.username=
    spring.cloud.config.server.git.password=
    spring.cloud.config.server.git.default-label=
    spring.cloud.config.server.git.clone-on-start=
    spring.cloud.config.username=
    spring.cloud.config.password=
    encrypt.key=

While the application properties need to provide the service with an OAuth2.0
server like keycloak, logging configuration etc.:

    server.shutdown=graceful

    # Configuration Variables
    service.variable.hostname=<service.hostname>
    service.variable.eureka.server.name=<eureka.server.name>
    service.variable.eureka.server.port=<eureka.server.port>
    service.variable.keycloak.server.name=<keycloak.server.name>
    service.variable.keycloak.server.port=<keycloak.server.port>
    service.variable.keycloak.server.realm=<keycloak.realm>
    
    # Logging Configuration
    logging.file.name=/var/log/${spring.application.name}.log
    logging.file.max-size=10MB
    logging.pattern.rolling-file-name=${spring.application.name}-%d{yyyy-MM-dd}.%i.log
    
    # Management Endpoints
    management.endpoint.logfile.external-file=/var/log/${spring.application.name}.log
    management.endpoints.web.exposure.include=*
    management.endpoint.health.show-details=when_authorized
    management.endpoint.health.probes.enabled=true
    
    # The Spring Cloud Discovery Config
    spring.cloud.config.discovery.service-id=eureka
    spring.cloud.config.allowOverride=true
    spring.cloud.config.overrideNone=true
    
    # Eureka Client Configuration
    eureka.client.service-url.defaultZone=http://${service.variable.eureka.server.name}:${service.variable.eureka.server.port}/eureka/
    eureka.client.register-with-eureka=false
    eureka.client.fetch-registry=true
    eureka.client.initialInstanceInfoReplicationIntervalSeconds=10
    eureka.client.registryFetchIntervalSeconds=10
    eureka.instance.preferIpAddress=false
    eureka.instance.leaseRenewalIntervalInSeconds=10
    eureka.instance.metadata-map.startup=${random.int}
    
    # Spring-boot Admin Configuration
    spring.boot.admin.context-path=/admin
    spring.boot.admin.instance-proxy.ignored-headers=Cookie,Set-Cookie
    
    # Keycloak Configuration
    spring.security.oauth2.client.registration.keycloak.client-id=eureka
    spring.security.oauth2.client.registration.keycloak.client-secret=<changeit>
    spring.security.oauth2.client.registration.keycloak.client-name=Keycloak
    spring.security.oauth2.client.registration.keycloak.provider=keycloak
    spring.security.oauth2.client.registration.keycloak.authorization-grant-type=authorization_code
    spring.security.oauth2.client.registration.keycloak.scope=openid
    spring.security.oauth2.client.registration.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}
    spring.security.oauth2.client.provider.keycloak.issuer-uri=http://${service.variable.keycloak.server.name}:${service.variable.keycloak.server.port}/realms/${service.variable.keycloak.server.realm}
    spring.security.oauth2.client.provider.keycloak.user-name-attribute=preferred_username
    spring.security.oauth2.resourceserver.jwt.issuer-uri=http://${service.variable.keycloak.server.name}:${service.variable.keycloak.server.port}/realms/${service.variable.keycloak.server.realm}
    
    # Spring Boot Admin Security
    spring.security.oauth2.client.registration.sba.client-id=eureka
    spring.security.oauth2.client.registration.sba.client-secret=<changeit>
    spring.security.oauth2.client.registration.sba.authorization-grant-type=client_credentials
    spring.security.oauth2.client.registration.sba.scope=web-origins,openid
    spring.security.oauth2.client.provider.sba.token-uri=http://${service.variable.keycloak.server.name}:${service.variable.keycloak.server.port}/realms/${service.variable.keycloak.server.realm}/protocol/openid-connect/token

## Operation

In order for the e-Navigation Service Architecture to correctly route the
incoming requests to the appropriate microservices, it first needs to know how
to locate each of them. This can be achieved either by the provision of a
configuration file with the available routes, or dynamically by a service
registry component, such as this.

Apart from its primary operation, the “Eureka” service is also able to provide
extensive monitoring on the internal architecture components through the
introduction of the Spring Boot Admin web interface. This is a separate module
that uses the Springboot actuator monitoring endpoints (if available) to display
all the relevant information in a single location. It is noted that the actuator
endpoints can be individually enabled for each of the involved microservices,
and are also protected by the OpenID Connect authorisation server.

In order to avoid unauthorised access to the actuator endpoints and the “Eureka”
service administration interface, the Keycloak role-based authorisation is being
utilised and a set of specific roles have been introduced. Under the current
configuration, actuators are only accessible for users with the “actuator” role,
while the “Eureka” administration interface is only accessible for users with
the “admin” role. The “Eureka” microservice service account is granted with the
“actuator” role for each of the monitored applications. The “Eureka” “admin”
role on the other hand is applicable only for human users. It has to be stressed
at this point that the aforementioned technique depends on all microservices
explicitly requiring the “actuator” role for requests on their actuator
endpoints.

Finally, if the cloud configuration mode is enabled, as mentioned previously,
it is able to expose an online configuration repository, thus removing the
requirement of supplying individual configuration files to the corresponding
services.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to
discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

Distributed under the Apache License, Version 2.0. See [LICENSE](./LICENSE.md)
for more information.

## Contact

Nikolaos Vastardis - Nikolaos.Vastardis@gla-rad.org
