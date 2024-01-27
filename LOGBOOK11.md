# **Week #11**

## **SEEDs Lab**

https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_PKI/

## Task 1 - Becoming a Certificate Authority (CA)

The objective of this task is to make ourselves a root CA, and generate a certificate for this CA.
In order for OpenSSL to create certificates, we need to have a configuration file. Firstly, we copy openSSL's default configuration file into our current directory.  

![screenshot1](screenshots/LOGBOOK11/screenshot1.png)

After making the required changes on the configuration file, we create the necessary directories and files.

![screenshot2](screenshots/LOGBOOK11/screenshot2.png)

Finally we create a self-signed certificate for the CA, which will make it fully trusted.

![screenshot3](screenshots/LOGBOOK11/screenshot3.png)

We use the following commands to look at the decoded content of the X509 certificate and the RSA key.

```
openssl x509 -in ca.crt -text -noout
openssl rsa -in ca.key -text -noout
```

The following content was displayed:

![screenshot4](screenshots/LOGBOOK11/screenshot4.png)

![screenshot5](screenshots/LOGBOOK11/screenshot5.png)

Looking at the content of the resulting files we can answer the following questions:

1. What part of the certificate indicates this is a CA’s certificate?
* Basic constraints: flag identifying certificate is CA.

![screenshot6](screenshots/LOGBOOK11/screenshot6.png)

2. What part of the certificate indicates this is a self-signed certificate?
* Issuer and Subject of certificate are the same.

![screenshot7](screenshots/LOGBOOK11/screenshot7.png)

3. In the RSA algorithm, we have a public exponent e, a private exponent d, a modulus n, and two secret
numbers p and q, such that n = pq. Please identify the values for these elements in your certificate
and key files.
* n is modulus, e is public exponent, d is private exponent, and p and q are prime1 and prime2.

![screenshot8](screenshots/LOGBOOK11/screenshot8.png)
![screenshot9](screenshots/LOGBOOK11/screenshot9.png)
![screenshot10](screenshots/LOGBOOK11/screenshot10.png)

## Task 2: Generating a Certificate Request for Your Web Server

Switching sides, now as a company, in this case bank32.com, we want to get a public key certificate from the previously mentioned CA. The objective of this task is to generate a Certificate Signing Request (CSR), which will then be sent to the CA, who will verify the identity information in the request, and then generate a certificate.

First thing we need to do is to generate a Certificate Signing Request (CSR). Due to the hostname matching policy enforced by browsers, the common name in a certificate must match with the server's hostname. Using the SAN extension, it is possible to specify several hostnames. Therefore our CSR creation command should look like this. 

![screenshot11](screenshots/LOGBOOK11/screenshot11.png)

We use the following commands to look at the decoded content of the CSR and private key files.

```
openssl req -in server.csr -text -noout
openssl rsa -in server.key -text -noout
```

The following content was displayed:

![screenshot12](screenshots/LOGBOOK11/screenshot12.png)

![screenshot13](screenshots/LOGBOOK11/screenshot13.png)

## Task 3: Generating a Certificate for your server

In this takk, we will To sign the certificate we need to type a command that turns the certificate signing request (server.csr) into an X509 certificate (server.crt), using the CA’s ca.crt and ca.key. Before that we need to make some changes on the configuration file. For security reasons, the default setting in openssl.cnf does not allow the `openssl ca` command to copy the extension field from the request to the final certificate, therefore to enable that functionality we need to uncomment the `copy_extension` line on the configuration file. 

![screenshot14](screenshots/LOGBOOK11/screenshot14.png)

Our certificate signing command should look like this. 

![screenshot15](screenshots/LOGBOOK11/screenshot15.png)

On the previous image we can see the alternetive names on the `X509v3 Subject Alternative Name` field.

## Task 4: Deploying Certificate in an Apache-Based HTTPS Website

In this task, we will be to set up an HTTPS website based Apache.

Via the VirtualHost file we can specify were the servers's certicate and private key are.

![screenshot16](screenshots/LOGBOOK11/screenshot16.png)

Now we need to enable Apache’s ssl module and then enable the website.

```
a2enmod ssl
a2ensite bank32_apache_ssl
```

For that we started the docker container that already executes the above commands.

![screenshot17](screenshots/LOGBOOK11/screenshot17.png)

After that we stored the certificate and private key files on the right files and using the following command, and specifying the password for decryption, we start the apache server.

```
service apache2 start
```

![screenshot18](screenshots/LOGBOOK11/screenshot18.png)

After that we couldn't access the site because we need to load the certificate into Firefox. We loaded the certificate as indicated in the guide and were able to access the website.

![screenshot19](screenshots/LOGBOOK11/screenshot19.png)
![screenshot20](screenshots/LOGBOOK11/screenshot20.png)


## Task 5: Launching a Man-In-The-Middle Attack
The objective of this task is to show why the Man-In-the-middle attack could be defeated by PKI.

First we start by reusing the same setup we did before, only difference is we change the name server in the virtualhost file to `www.facebook.com`, this will be our example.

![screenshot21](screenshots/LOGBOOK11/screenshot21.png)

In order to to emulate the result of a DNS cache positing attack we modify the machine’s `/etc/hosts` file by mapping the hostname `www.facebook.com` to our malicious web server.

![screenshot22](screenshots/LOGBOOK11/screenshot22.png)

When we browse the target website, this happens:

![screenshot23](screenshots/LOGBOOK11/screenshot23.png)

The reason why we cannot access the website is because the browser knows the certificate does not match the website therefore warns the user of a potential attack, which proves the MITM attack is defeated by the use of PKI infrastructure.

## Task 6: Launching a Man-In-The-Middle Attack with a Compromised CA

In this task, we assume that the root CA created in Task 1 is compromised by an attacker, and its private key
is stolen. The objective of this task is to show the consequences of the CA being compromised.

If the attacker has control over the CA he can generate certificates at will. Using the previous website example, lets generate a CSR for that website.

![screenshot24](screenshots/LOGBOOK11/screenshot24.png)

Then the attacker authorizes the CSR.

![screenshot25](screenshots/LOGBOOK11/screenshot25.png)

And finally, he prepares the trap with an "oficial" certificate, the same steps of task 4.

![screenshot26](screenshots/LOGBOOK11/screenshot26.png)

Finally when the user browses the target website this happens.

![screenshot27](screenshots/LOGBOOK11/screenshot27.png)

Firefox does not complain because the certificate makes sense with the website, it thinks the certificate is oficial and thus represents the website, giving no warning to the user.