require 'openssl'
require 'socket'
module EzSSL

  class Server

    attr_reader :read
    def initialize(ip,port,length=2048)
      @socket=TCPServer.open(ip,port)
      @pair=OpenSSL::PKey::RSA.new(length)
      @pubkey=@pair.public_key
      @read=@pubkey.public_encrypt('hello').length
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

    attr_reader :key, :pubkey

    def initialize(ip,port,length=2048)
      @pair=OpenSSL::PKey::RSA.new(length)
      @pubkey=@pair.public_key
      @socket=TCPSocket.new(ip,port)
      @read=@pubkey.public_encrypt('hello').length
      go=true
      key=''
      while go
        msg=@socket.gets
        key+=msg
        go=false if msg=="-----END PUBLIC KEY-----\n"
      end
      @socket.puts @pubkey.to_s
      @key=OpenSSL::PKey::RSA.new(key)
    end

    # Returns the maximum length of string that can be encypted with a given key
    # 
    # @param [Object] The OpenSSL object to test
    # @return [Integer] The maximum length of string that can be encrypted with the given key
    def max_len(key)
      return key.public_encrypt('test').length
    end

    # Sends a string (msg) to the server
    #
    # @param msg [String] The sting being sent to the server
    # @raise [ArgumentError] if the message being sent is too large for the OpenSSL::PKey::RSA object
    def puts(msg)
      raise ArgumentError, "Message is too large to encrypt with the current key. (Max Length:#{max_len(@key)})" if msg.length > max_len(@key)
      @socket.write @key.public_encrypt(msg)
      return nil
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

    attr_reader :send
    def initialize(client,key,server)
      # The represented client
      @client=client
      # The public key of the represented client
      @key=OpenSSL::PKey::RSA.new(key)
      @send=@key.public_encrypt('test lol').length
      @server=server
    end

    # Sends a string (msg) to the represented client
    #  
    # @param msg [String] The message being sent to the client
    # @raise [ArgumentError] if the message being sent is too large for the OpenSSL::PKey::RSA object
    def puts(msg)
      raise ArgumentError, "Message is too large to encrypt with the current key. (Max Length:#{max_len(@key)})" if msg.length > max_len(@key)
      @client.write @key.public_encrypt(msg)
      return nil
    end

    # Returns the maximum length of string that can be encypted with a given key
    # 
    # @param [Object] The OpenSSL object to test
    # @return [Integer] The maximum length of string that can be encrypted with the given key
    def max_len(key)
      return key.public_encrypt('test').length
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
