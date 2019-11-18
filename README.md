# kafka-sasl-ssl-principal-builder


This service provides custom principal builder class for Kafka Authentication (SSL and SASL)

## Build

Run the build command for this service from hyodon home directory
```
mvn -e clean package
```

## Configuration

Copy the library ```target/kafka-sasl-ssl-principal-builder-1.0.jar``` to all the broker nodes under ```/usr/share/java/kafka``` directory.

Configure brokers to use this class in properties file
```
# Configuration to build custom Kerberos principal name, used for REST clients
# SSL principals are of the format "CN=appuser1.corp.example.com,O=Example Inc.,L=San Jose,ST=CA,C=US"
# We'll extract "appuser1" from the certificate that is passed by REST Proxy
principal.builder.class=com.example.kafka.security.auth.principalBuilder
```

By default, principal builder class reads broker configurations from ```/etc/kafka/server.properties```. This can be overridden by specifying an environment variable like so: 

```
[Service]
Environment="PRINCIPAL_BUILDER_KAFKA_CONFIG_FILE=/custom_directory/custom_file.properties"
```

If ```DEBUG``` logging is enabled in Kafka, one can see where the library is reading from and what the value for ```sasl.kerberos.principal.to.local.rules``` looks like.

