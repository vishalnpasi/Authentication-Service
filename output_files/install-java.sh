

echo "Commenting security Config for tls"
sed -i "/jdk.tls.disabledAlgorithms=SSLv3/d" ../opt/java/openjdk/conf/security/java.security

sed -i "734i\# jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, \/" ../opt/java/openjdk/conf/security/java.security

sed -i "/DH keySize < 1024/d" ../opt/java/openjdk/conf/security/java.security

sed -i "735i\# DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \/" ../opt/java/openjdk/conf/security/java.security

sed -i "/include jdk.disabled.namedCurves/d" ../opt/java/openjdk/conf/security/java.security

sed -i "635i\ include jdk.disabled.namedCurves" ../opt/java/openjdk/conf/security/java.security
sed -i "700i\ include jdk.disabled.namedCurves" ../opt/java/openjdk/conf/security/java.security
sed -i "736i\# include jdk.disabled.namedCurves" ../opt/java/openjdk/conf/security/java.security

echo "Commenting done"
