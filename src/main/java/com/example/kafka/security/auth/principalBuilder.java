/*
 * ADOBE CONFIDENTIAL. Copyright 2016 Adobe Systems Incorporated. All Rights Reserved. NOTICE: All information contained
 * herein is, and remains the property of Adobe Systems Incorporated and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Adobe Systems Incorporated and its suppliers and are protected
 * by all applicable intellectual property laws, including trade secret and copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden unless prior written permission is obtained
 * from Adobe Systems Incorporated.
 */

package com.example.kafka.security.auth;

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.SaslServer;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.PlaintextAuthenticationContext;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.security.kerberos.KerberosName;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.apache.kafka.common.utils.Java;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class principalBuilder implements KafkaPrincipalBuilder {

    private static final Logger logger = LoggerFactory.getLogger(principalBuilder.class.getName());

    /*
     * Check if we are supposed to read broker configs from non-default location
     */
    private static final String KAFKA_CONFIG_FILE =
            System.getenv("PRINCIPAL_BUILDER_KAFKA_CONFIG_FILE") != null ?
                    System.getenv("PRINCIPAL_BUILDER_KAFKA_CONFIG_FILE")  : "/etc/kafka/server.properties";

    private KerberosShortNamer kerberosShortNamer;
    private String[] kerberosPrincipalToLocalRules;
    private List<String> principalToLocalRules;

    public void principalBuilder() {

        logger.debug("Kafka Configuration File: " + KAFKA_CONFIG_FILE);

        Properties properties = new Properties();

        try {
            FileInputStream configFile = new FileInputStream(KAFKA_CONFIG_FILE);
            properties.load(configFile);
        } catch (Exception e) {
            throw new KafkaException("Couldn't read Broker Configuration file. Reason: ", e);
        }

        try {
            kerberosPrincipalToLocalRules =
                    properties.getProperty(BrokerSecurityConfigs.SASL_KERBEROS_PRINCIPAL_TO_LOCAL_RULES_CONFIG).split(",");
            principalToLocalRules = Arrays.asList(kerberosPrincipalToLocalRules);
            logger.debug(BrokerSecurityConfigs.SASL_KERBEROS_PRINCIPAL_TO_LOCAL_RULES_CONFIG + " is set. Value: "
                    + principalToLocalRules);
        } catch (NullPointerException e) {
            /*
             * Key is null, so we need to set the rules
             * Check https://community.hortonworks.com/articles/14463/auth-to-local-rules-syntax.html for syntax
             */
            principalToLocalRules = Arrays.asList(
                    "RULE:[1:$1]",
                    "RULE:[2:$1]",
                    "DEFAULT"
            );
            logger.debug(BrokerSecurityConfigs.SASL_KERBEROS_PRINCIPAL_TO_LOCAL_RULES_CONFIG + " not set in config. Using default rules: "
                    + principalToLocalRules);
        } catch (Exception e) {
            throw new KafkaException("Failed reading " +  BrokerSecurityConfigs.SASL_KERBEROS_PRINCIPAL_TO_LOCAL_RULES_CONFIG + " Reason: ", e);
        }

        try {
            kerberosShortNamer = KerberosShortNamer.fromUnparsedRules(defaultKerberosRealm(), principalToLocalRules);
            logger.debug("Realm is : " + defaultKerberosRealm());
        } catch (Exception e) {
            throw new KafkaException("Failed building short name. Reason: ", e);
        }

    }

    @Override
    public KafkaPrincipal build(AuthenticationContext context) {

        if (context instanceof PlaintextAuthenticationContext) {
            return KafkaPrincipal.ANONYMOUS;

        } else if (context instanceof SslAuthenticationContext) {
            SSLSession sslSession = ((SslAuthenticationContext) context).session();

            try {
                return SSLToKafkaPrincipal(sslSession.getPeerPrincipal());
            } catch (SSLPeerUnverifiedException se) {
                return KafkaPrincipal.ANONYMOUS;
            }

        } else if (context instanceof SaslAuthenticationContext) {
            SaslServer saslServer = ((SaslAuthenticationContext) context).server();

            if (SaslConfigs.GSSAPI_MECHANISM.equals(saslServer.getMechanismName())) {
                return SASLToKafkaPrincipal(saslServer.getAuthorizationID());
            } else {
                return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, saslServer.getAuthorizationID());
            }

        } else {
            throw new IllegalArgumentException("Unhandled authentication context type: " + context.getClass().getName());
        }
    }

    private KafkaPrincipal SASLToKafkaPrincipal(String authorizationId) {
        KerberosName kerberosName = KerberosName.parse(authorizationId);
        try {
            String shortName = kerberosShortNamer.shortName(kerberosName);
            return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, shortName);
        } catch (IOException e) {
            throw new KafkaException("Failed to set name for '" + kerberosName + "' based on Kerberos authentication rules.", e);
        }
    }

    public KafkaPrincipal SSLToKafkaPrincipal(Principal principal) throws KafkaException {
        KafkaPrincipal kafkaPrincipal = new KafkaPrincipal(KafkaPrincipal.USER_TYPE, principal.getName());

        try {
            if ((principal instanceof X500Principal)
                    && !principal.getName().equals(KafkaPrincipal.ANONYMOUS)) {

                String[] split = null;

                try {
                    split = principal.getName().split(",");
                    final String dn = split[0].split("=")[1].split(".corp.example.com")[0];
                    kafkaPrincipal = new KafkaPrincipal(KafkaPrincipal.USER_TYPE, dn);
                    logger.debug("SSL Principal:" + kafkaPrincipal);
                    return kafkaPrincipal;
                } catch (Exception e) {
                    throw new KafkaException("failed building principal. Reason: ", e);
                }
            } else {
                logger.info("Skipping principalBuilder");
            }
            return kafkaPrincipal;
        } catch (Exception e) {
            throw new KafkaException("Failed to build principal. Reason: ", e);
        }

    }

    private static String defaultKerberosRealm() throws ClassNotFoundException, NoSuchMethodException,
            IllegalArgumentException, IllegalAccessException, InvocationTargetException {

        Object kerbConf;
        Class<?> classRef;
        Method getInstanceMethod;
        Method getDefaultRealmMethod;
        if (Java.isIbmJdk()) {
            classRef = Class.forName("com.ibm.security.krb5.internal.Config");
        } else {
            classRef = Class.forName("sun.security.krb5.Config");
        }
        getInstanceMethod = classRef.getMethod("getInstance", new Class[0]);
        kerbConf = getInstanceMethod.invoke(classRef, new Object[0]);
        getDefaultRealmMethod = classRef.getDeclaredMethod("getDefaultRealm", new Class[0]);
        return (String) getDefaultRealmMethod.invoke(kerbConf, new Object[0]);
    }

}
