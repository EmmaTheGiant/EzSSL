require 'openssl'
require 'socket'
module EzSSL

  class Server
    
    attr_reader :read, :length

    def initialize(ip,port,length=2048)
      @length=length # bit length of private key [readable]
      @socket=TCPServer.open(ip,port) # the server
      @pair=OpenSSL::PKey::RSA.new(length) # the server keypair
      @pubkey=@pair.public_key
      @read=@pubkey.public_encrypt('hello').length # byte length to be read by the Handle object
    end

    # Accepts a client connection, and returns a Handle object for communication
    # 
    # @return [Object] The Handle object
    def accept()
      client=@socket.accept
      client.puts @pubkey.to_s
      go=true
      key=''
      while go
        msg=client.gets
        key+=msg
        go=false if msg=="-----END PUBLIC KEY-----\n"
      end
      return Handle.new(client,key,self)
    end

    # Decrypt a message without direct access to the private key
    # 
    # @param msg [String] The encrypted message
    # @return [String] The decrypted message
    def decrypt(msg)
      return @pair.private_decrypt(msg)
    end
    
  end

  class Client

    attr_reader :key, :pubkey, :length, :max

    def initialize(ip,port,length=2048)
      @length=length # bit length of private key
      @pair=OpenSSL::PKey::RSA.new(length)
      @pubkey=@pair.public_key # clients public key
      @socket=TCPSocket.new(ip,port)
      @read=@pubkey.public_encrypt('hello').length

      # recieve the key frome the server
      go=true
      key=''
      while go
        msg=@socket.gets
        key+=msg
        go=false if msg=="-----END PUBLIC KEY-----\n"
      end

      #give server public key
      @socket.puts @pubkey.to_s
      @key=OpenSSL::PKey::RSA.new(key) # the servers public key
      
      @max=((self.gets().to_i)/8).floor - 11
      self.puts @length.to_s
    end

    # Sends a string (msg) to the server
    #
    # @param msg [String] The sting being sent to the server
    # @raise [ArgumentError] if the message being sent is too large for the OpenSSL::PKey::RSA object
    def puts(msg)
      raise ArgumentError, 'Message too big' if msg.length>@max
      @socket.write @key.public_encrypt(msg)
    end

    # Recieves a string from the server
    # 
    # @return [String] The message from the server
    def gets()
      msg=@socket.read(@read)
      return @pair.private_decrypt(msg)
    end
  end

  private

  # The object that allows communication from Server to Client.
  class Handle
    attr_reader :max
    # the client already has the servers pubkey, and the server has the clients pubkey

    def initialize(client,key,server)
      # The represented client
      @client=client
      # The public key of the represented client
      @key=OpenSSL::PKey::RSA.new(key)
      @server=server
      @max=256
      self.puts @server.length.to_s
      @max=@max=((self.gets().to_i)/8).floor - 11
    end

    # Sends a string (msg) to the represented client
    #  
    # @param msg [String] The message being sent to the client
    # @raise [ArgumentError] if the message being sent is too large for the OpenSSL::PKey::RSA object
    def puts(msg)
      raise ArgumentError, 'Message too big' if msg.length>@max
      @client.write @key.public_encrypt(msg)
    end

    # Recieves a string from the client
    # 
    # @return [String] The message sent from the client
    def gets()
      msg=@client.read(@server.read)
      return @server.decrypt(msg)
    end

    # Closes the client remotely
    def close
      @client.close
    end

  end

end
