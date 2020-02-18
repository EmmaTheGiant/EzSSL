require 'openssl'
require 'socket'
module EzSSL
  class Server
    attr_reader :pubkey
    @@rsa=OpenSSL::PKey::RSA.new(2048)
    def initialize(ip,port)
      @server=TCPServer.new(ip,port)
    end
    def accept()
      client=@server.accept
      return Handle.new(client,self)
    end
    def rsa_decrypt(msg)
      return @@rsa.private_decrypt(msg)
    end
    def pubkey
      return @@rsa.public_key.to_s
    end
  end
  
  class Client
    def initialize(ip,port)
      @socket=TCPSocket.new(ip,port)
      @rsa=OpenSSL::PKey::RSA.new(2048)
      @cip=OpenSSL::Cipher::AES256.new(:CBC).encrypt()
      @dec=OpenSSL::Cipher::AES256.new(:CBC).decrypt()
      #server=>client
      key=''
      line=@socket.gets
      until line=="\n"
        key+=line
        line=@socket.gets
      end
      @server_rsa=OpenSSL::PKey::RSA.new(key)
      @socket.puts @rsa.public_key.to_s
      @socket.puts ""
    end
    
    def puts(msg)
      key=@cip.random_key()
      iv=@cip.random_iv()
      enc=@cip.update(msg)+@cip.final
      @socket.write(iv)
      @socket.write(@server_rsa.public_encrypt(key))
      @socket.puts enc.length
      @socket.write(enc)
    end
    
    def gets()
      @dec.iv=@socket.read(16)
      @dec.key=@rsa.private_decrypt(@socket.read(256))
      len=@socket.gets.to_i
      msg=@socket.read(len)
      return @dec.update(msg)+@dec.final
    end
    
  end
  
  private
  class Handle
    def initialize(client,server)
      @client=client
      @server=server
      @cip=OpenSSL::Cipher::AES256.new(:CBC).encrypt()
      @dec=OpenSSL::Cipher::AES256.new(:CBC).decrypt()
      #swap rsa keys
      #server=>client
      client.puts server.pubkey
      client.puts ""
      #client=>server
      key=''
      line=client.gets
      until line=="\n"
        key+=line
        line=client.gets
      end
      #make rsa key
      @rsa=OpenSSL::PKey::RSA.new(key)
    end
    
    def puts(msg)
      key=@cip.random_key()
      iv=@cip.random_iv()
      enc=@cip.update(msg)+@cip.final
      @client.write(iv)
      @client.write(@rsa.public_encrypt(key))
      @client.puts enc.length
      @client.write(enc)
    end
    
    def gets()
      @dec.iv=@client.read(16)
      @dec.key=@server.rsa_decrypt(@client.read(256))
      len=@client.gets.to_i
      msg=@client.read(len)
      return @dec.update(msg)+@dec.final
    end
    
    def close()
      @client.close()
    end
  end
end
