package org.bouncycastle.jsse.provider.test;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;

import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class SSLEngineDelegatedTaskTest
    extends TestCase
{
    private static final String CIPHER_SUITE = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    private static final String PROTOCOL = "TLSv1.2";
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    public void testServerUnwrapDelegatesSlowSigner()
        throws Exception
    {
        BlockingSignerControl signerControl = new BlockingSignerControl(750L, false);
        EnginePair engines = createEnginePair(signerControl);

        SSLEngineResult clientHello = engines.client.wrap(EMPTY_BUFFER, engines.clientToServer);
        assertEquals(HandshakeStatus.NEED_UNWRAP, clientHello.getHandshakeStatus());
        assertTrue(clientHello.bytesProduced() > 0);

        ((java.nio.Buffer)engines.clientToServer).flip();

        long start = System.currentTimeMillis();
        SSLEngineResult serverResult = engines.server.unwrap(engines.clientToServer, engines.serverIn);
        long elapsed = System.currentTimeMillis() - start;

        assertEquals(HandshakeStatus.NEED_TASK, serverResult.getHandshakeStatus());
        assertTrue("unwrap blocked for " + elapsed + "ms", elapsed < signerControl.getDelayMillis());
        assertEquals(0, signerControl.getSignCount());
        assertEquals(HandshakeStatus.NEED_TASK, engines.server.getHandshakeStatus());

        engines.clientToServer.compact();

        Runnable task = engines.server.getDelegatedTask();
        assertNotNull(task);
        assertNull(engines.server.getDelegatedTask());

        Thread worker = new Thread(task, "BCJSSE delegated task test");
        worker.start();

        assertTrue(signerControl.awaitSignStarted(5000L));
        assertSame(worker, signerControl.getSigningThread());
        assertEquals(1, signerControl.getSignCount());

        start = System.currentTimeMillis();
        SSLEngineResult pendingTaskResult = engines.server.wrap(EMPTY_BUFFER, engines.serverToClient);
        elapsed = System.currentTimeMillis() - start;

        assertEquals(HandshakeStatus.NEED_TASK, pendingTaskResult.getHandshakeStatus());
        assertEquals(0, pendingTaskResult.bytesProduced());
        assertTrue("wrap blocked for " + elapsed + "ms", elapsed < signerControl.getDelayMillis());

        worker.join(5000L);
        assertFalse(worker.isAlive());
        assertNull(engines.server.getDelegatedTask());

        completeHandshake(engines);
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, engines.client.getHandshakeStatus());
        assertEquals(HandshakeStatus.NOT_HANDSHAKING, engines.server.getHandshakeStatus());
    }

    public void testDelegatedTaskExceptionPropagatesFromLaterWrap()
        throws Exception
    {
        BlockingSignerControl signerControl = new BlockingSignerControl(0L, true);
        EnginePair engines = createEnginePair(signerControl);

        SSLEngineResult clientHello = engines.client.wrap(EMPTY_BUFFER, engines.clientToServer);
        assertEquals(HandshakeStatus.NEED_UNWRAP, clientHello.getHandshakeStatus());

        ((java.nio.Buffer)engines.clientToServer).flip();

        SSLEngineResult serverResult = engines.server.unwrap(engines.clientToServer, engines.serverIn);
        assertEquals(HandshakeStatus.NEED_TASK, serverResult.getHandshakeStatus());

        Runnable task = engines.server.getDelegatedTask();
        assertNotNull(task);
        task.run();

        assertEquals(HandshakeStatus.NEED_WRAP, engines.server.getHandshakeStatus());
        try
        {
            engines.server.wrap(EMPTY_BUFFER, engines.serverToClient);
            fail("Expected SSLException from delegated signer failure");
        }
        catch (SSLException e)
        {
            assertNotNull(e.getCause());
        }
    }

    private static EnginePair createEnginePair(BlockingSignerControl signerControl)
        throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair serverKeyPair = TestUtils.generateECKeyPair();
        X509Certificate serverCert = TestUtils.generateRootCert(serverKeyPair);

        KeyStore serverStore = KeyStore.getInstance("JKS");
        serverStore.load(null, null);
        serverStore.setKeyEntry("server", serverKeyPair.getPrivate(), keyPass, new X509Certificate[]{ serverCert });

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", serverCert);

        Provider clientProvider = ProviderUtils.createProviderBCJSSE(false);
        Provider serverProvider = new BouncyCastleJsseProvider(false, new BlockingJcaTlsCryptoProvider(signerControl));

        SSLContext clientContext = createClientContext(clientProvider, trustStore);
        SSLContext serverContext = createServerContext(serverProvider, serverStore, keyPass);

        SSLEngine client = clientContext.createSSLEngine();
        client.setEnabledCipherSuites(new String[]{ CIPHER_SUITE });
        client.setEnabledProtocols(new String[]{ PROTOCOL });
        client.setUseClientMode(true);

        SSLEngine server = serverContext.createSSLEngine();
        server.setEnabledCipherSuites(new String[]{ CIPHER_SUITE });
        server.setEnabledProtocols(new String[]{ PROTOCOL });
        server.setUseClientMode(false);
        server.setWantClientAuth(false);

        int packetBufferSize = Math.max(client.getSession().getPacketBufferSize(), server.getSession().getPacketBufferSize());
        int applicationBufferSize = Math.max(client.getSession().getApplicationBufferSize(),
            server.getSession().getApplicationBufferSize());

        return new EnginePair(client, server, ByteBuffer.allocate(packetBufferSize * 4),
            ByteBuffer.allocate(packetBufferSize * 4), ByteBuffer.allocate(applicationBufferSize),
            ByteBuffer.allocate(applicationBufferSize));
    }

    private static SSLContext createClientContext(Provider provider, KeyStore trustStore)
        throws Exception
    {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", provider);
        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS", provider);
        context.init(null, trustManagerFactory.getTrustManagers(),
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));
        return context;
    }

    private static SSLContext createServerContext(Provider provider, KeyStore keyStore, char[] keyPass)
        throws Exception
    {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("PKIX", provider);
        keyManagerFactory.init(keyStore, keyPass);

        SSLContext context = SSLContext.getInstance("TLS", provider);
        context.init(keyManagerFactory.getKeyManagers(), null,
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));
        return context;
    }

    private static void completeHandshake(EnginePair engines)
        throws Exception
    {
        for (int i = 0; i < 200; ++i)
        {
            boolean progress = false;

            progress |= wrap(engines.client, engines.clientToServer);
            progress |= wrap(engines.server, engines.serverToClient);

            ((java.nio.Buffer)engines.clientToServer).flip();
            progress |= unwrap(engines.server, engines.clientToServer, engines.serverIn);
            engines.clientToServer.compact();

            ((java.nio.Buffer)engines.serverToClient).flip();
            progress |= unwrap(engines.client, engines.serverToClient, engines.clientIn);
            engines.serverToClient.compact();

            if (HandshakeStatus.NOT_HANDSHAKING == engines.client.getHandshakeStatus()
                && HandshakeStatus.NOT_HANDSHAKING == engines.server.getHandshakeStatus())
            {
                return;
            }

            if (!progress)
            {
                fail("Handshake made no progress");
            }
        }

        fail("Handshake did not complete");
    }

    private static boolean wrap(SSLEngine engine, ByteBuffer destination)
        throws Exception
    {
        SSLEngineResult result = engine.wrap(EMPTY_BUFFER, destination);
        return madeProgress(result) | runDelegatedTasks(engine);
    }

    private static boolean unwrap(SSLEngine engine, ByteBuffer source, ByteBuffer destination)
        throws Exception
    {
        SSLEngineResult result = engine.unwrap(source, destination);
        return madeProgress(result) | runDelegatedTasks(engine);
    }

    private static boolean madeProgress(SSLEngineResult result)
    {
        return result.bytesConsumed() > 0 || result.bytesProduced() > 0
            || HandshakeStatus.NEED_TASK == result.getHandshakeStatus();
    }

    private static boolean runDelegatedTasks(SSLEngine engine)
    {
        boolean result = false;
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null)
        {
            task.run();
            result = true;
        }
        return result;
    }

    private static final class EnginePair
    {
        final SSLEngine client;
        final SSLEngine server;
        final ByteBuffer clientToServer;
        final ByteBuffer serverToClient;
        final ByteBuffer clientIn;
        final ByteBuffer serverIn;

        EnginePair(SSLEngine client, SSLEngine server, ByteBuffer clientToServer, ByteBuffer serverToClient,
            ByteBuffer clientIn, ByteBuffer serverIn)
        {
            this.client = client;
            this.server = server;
            this.clientToServer = clientToServer;
            this.serverToClient = serverToClient;
            this.clientIn = clientIn;
            this.serverIn = serverIn;
        }
    }

    private static final class BlockingSignerControl
    {
        private final long delayMillis;
        private final boolean fail;
        private final AtomicInteger signCount = new AtomicInteger();
        private final CountDownLatch signStarted = new CountDownLatch(1);
        private volatile Thread signingThread;

        BlockingSignerControl(long delayMillis, boolean fail)
        {
            this.delayMillis = delayMillis;
            this.fail = fail;
        }

        long getDelayMillis()
        {
            return delayMillis;
        }

        int getSignCount()
        {
            return signCount.get();
        }

        Thread getSigningThread()
        {
            return signingThread;
        }

        boolean awaitSignStarted(long timeoutMillis)
            throws InterruptedException
        {
            return signStarted.await(timeoutMillis, TimeUnit.MILLISECONDS);
        }

        void beforeSign()
            throws SignatureException
        {
            signingThread = Thread.currentThread();
            signCount.incrementAndGet();
            signStarted.countDown();

            if (fail)
            {
                throw new SignatureException("delegated signer failure");
            }

            try
            {
                Thread.sleep(delayMillis);
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
                throw new SignatureException("delegated signer interrupted");
            }
        }
    }

    private static final class BlockingJcaTlsCryptoProvider
        extends JcaTlsCryptoProvider
    {
        private final BlockingSignerControl signerControl;

        BlockingJcaTlsCryptoProvider(BlockingSignerControl signerControl)
        {
            this.signerControl = signerControl;
        }

        public JcaTlsCrypto create(SecureRandom keyRandom, SecureRandom nonceRandom)
        {
            return new BlockingJcaTlsCrypto(new BlockingBCJcaJceHelper(signerControl), getAltHelper(), keyRandom,
                nonceRandom);
        }
    }

    private static final class BlockingJcaTlsCrypto
        extends JcaTlsCrypto
    {
        BlockingJcaTlsCrypto(JcaJceHelper helper, JcaJceHelper altHelper, SecureRandom entropySource,
            SecureRandom nonceEntropySource)
        {
            super(helper, altHelper, entropySource, nonceEntropySource);
        }
    }

    private static final class BlockingBCJcaJceHelper
        extends BCJcaJceHelper
    {
        private final BlockingSignerControl signerControl;

        BlockingBCJcaJceHelper(BlockingSignerControl signerControl)
        {
            this.signerControl = signerControl;
        }

        public Signature createSignature(String algorithm)
            throws java.security.NoSuchAlgorithmException
        {
            return new BlockingSignature(super.createSignature(algorithm), signerControl);
        }
    }

    private static final class BlockingSignature
        extends Signature
    {
        private final Signature delegate;
        private final BlockingSignerControl signerControl;

        BlockingSignature(Signature delegate, BlockingSignerControl signerControl)
        {
            super(delegate.getAlgorithm());
            this.delegate = delegate;
            this.signerControl = signerControl;
        }

        protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException
        {
            delegate.initVerify(publicKey);
        }

        protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException
        {
            delegate.initSign(privateKey);
        }

        protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException
        {
            delegate.initSign(privateKey, random);
        }

        protected void engineUpdate(byte b)
            throws SignatureException
        {
            delegate.update(b);
        }

        protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException
        {
            delegate.update(b, off, len);
        }

        protected byte[] engineSign()
            throws SignatureException
        {
            signerControl.beforeSign();
            return delegate.sign();
        }

        protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException
        {
            return delegate.verify(sigBytes);
        }

        protected void engineSetParameter(String param, Object value)
        {
            delegate.setParameter(param, value);
        }

        protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            delegate.setParameter(params);
        }

        protected Object engineGetParameter(String param)
        {
            return delegate.getParameter(param);
        }

        protected AlgorithmParameters engineGetParameters()
        {
            return delegate.getParameters();
        }
    }
}
