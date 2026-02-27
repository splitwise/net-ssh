unless ENV['NET_SSH_NO_ED25519']

  require_relative '../common'
  require 'net/ssh/authentication/ed25519_loader'
  require 'net/ssh/key_factory'
  require 'base64'

  module Authentication
    class TestOpenSSHPrivateKeyLoader < NetSSHTest
      def setup
        raise "No ED25519 set NET_SSH_NO_ED25519 to ignore this test" unless Net::SSH::Authentication::ED25519Loader::LOADED
      end

      def test_aes_cbc_key
        key = <<~PRIVATEKEY
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABAkbe7i7M
          lqGCSgPgr+ohv1AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHl0AyaA/DuN/ZYd
          7gbSDA1uCALeRaz2j/72tKkJQ6mrAAAAkIDyuOAcJhooRGOI1Vo3EWCaVWgQI7yT+Up2D8
          AOZ/xcOlcdrnSoVAPjYbeNGePuhShnSvzt3/ffzk8OAMkmVIfOukzQ1xRlySeFASWzXpZR
          gJ4xdOyaURZ2zGeie29WOWJfeNCf/sKrtE8GonVW85iLVBBM1tDga9ta2Dq872OGFS7/qi
          VCs5bN8YByGKbuxA==
          -----END OPENSSH PRIVATE KEY-----
        PRIVATEKEY
        pwd = 'test'

        privkey = Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(key, pwd)
        assert_kind_of(Net::SSH::Authentication::ED25519::PrivKey, privkey)
      end

      def test_aes256_gcm_key
        key = <<~PRIVATEKEY
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAAFmFlczI1Ni1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA
          AAGAAAABCCj7iTVdMrx15cLyopqOpcAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA
          IPDBX9jvz2qS9ZFU+F9x+vL+ef7rH8VPwCn6IJc4CaGhAAAAkEyIM5bCRB50LPxP9D4rtD
          EdReGh+wsN6/84u4Efw1QjRm/O6LJzJEDl3LV8ntDMWBqBN0q6OJL3eqICWYjAjOdPHLkl
          qmKYhrT+eWDqS/1KihyO46HkfKOWSM2fOQPcjqVsjSTJ3CV5oVkptuLB6ak8e/mmzplywv
          MjSA8aFdrtUGDJhpT7z46xURMJarvDkqvJZbw4PkmYWlfNRu3dXAI=
          -----END OPENSSH PRIVATE KEY-----
        PRIVATEKEY
        pwd = 'test'

        privkey = Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(key, pwd)
        assert_kind_of(Net::SSH::Authentication::ED25519::PrivKey, privkey)
      end

      def test_chacha20_poly1305_key
        key = <<~PRIVATEKEY
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAAHWNoYWNoYTIwLXBvbHkxMzA1QG9wZW5zc2guY29tAAAABm
          JjcnlwdAAAABgAAAAQYf8G9VsDZqFN+GKW7A0XewAAABgAAAABAAAAMwAAAAtzc2gtZWQy
          NTUxOQAAACAF+rfLEozMyDub+8gOsb+WssHKSzh+5ffWiyKC3efLfQAAAJDcniGJhUGXaK
          A7v6DMkskqZA70Sqs1Pjz4ahZ6uBXImAHk04VYskUkcD9FW6GkevWrQA69stLQcmMvuS1Y
          AyrWopSzwJ0HEZj55b5mnjH8Iob0jPVjAuf5vtjfFeb/rncVgprs6AtEVItgIwZ+LoJTLN
          yytSz1DNyO0oyZiowww6RMmr3lNjPHNtB71X4XZ3jDo7ySUF24MKmdsPiOjc+R
          -----END OPENSSH PRIVATE KEY-----
        PRIVATEKEY
        pwd = 'test'

        privkey = Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(key, pwd)
        assert_kind_of(Net::SSH::Authentication::ED25519::PrivKey, privkey)
      end

      def test_unencrypted_key; end
    end
  end
end
