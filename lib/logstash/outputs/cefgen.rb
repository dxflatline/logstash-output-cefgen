# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "logstash/util/socket_peer"

# An cefgen output that does nothing.
class LogStash::Outputs::Cefgen < LogStash::Outputs::Base
  config_name "cefgen"
  concurrency :single
 
  default :codec, "json"
  
  config :host, :validate => :string, :required => true
  config :port, :validate => :number, :required => true
  config :reconnect_interval, :validate => :number, :default => 10
  config :cefprefix, :validate => :string, :default => "cef_"

  
  class Client
    public
    def initialize(socket, logger)
      @socket = socket
      @logger = logger
      @queue  = Queue.new
    end

    public
    def run
      loop do
        begin
          @socket.write(@queue.pop)
        rescue => e
          @logger.warn("tcp output exception", :socket => @socket,
                       :exception => e)
          break
        end
      end
    end # def run

    public
    def write(msg)
      @queue.push(msg)
    end # def write
  end # class Client

  public
  def register
    require "socket"
    require "stud/try"
    client_socket = nil
    @codec.on_event do |event, payload|
      begin
        client_socket = connect unless client_socket
        r,w,e = IO.select([client_socket], [client_socket], [client_socket], nil)
        # don't expect any reads, but a readable socket might
        # mean the remote end closed, so read it and throw it away.
        # we'll get an EOFError if it happens.
        client_socket.sysread(16384) if r.any?

        # Now send the payload
        client_socket.syswrite(event.get('cef_output')) if w.any?
      rescue => e
        @logger.warn("tcp output exception", :host => @host, :port => @port,
                     :exception => e, :backtrace => e.backtrace)
        client_socket.close rescue nil
        client_socket = nil
        sleep @reconnect_interval
        retry
      end
    end
  end # def register


  private
  def connect
    Stud::try do
      client_socket = TCPSocket.new(@host, @port)
      client_socket.instance_eval { class << self; include ::LogStash::Util::SocketPeer end }
      @logger.debug("Opened connection", :client => "#{client_socket.peer}")
      return client_socket
    end
  end # def connect

 
  public
  def receive(event)
    cef_output = "CEF:0"
    # Add CEF header
    cef_output = "#{cef_output}|#{event.get('cef_deviceVendor')}|#{event.get('cef_deviceProduct')}|1.0|#{event.get('cef_deviceEventClassId')}|#{event.get('cef_name')}|#{event.get('cef_severity')}| "
    # Loop through all JSON fields to find starting with cefprefix
    event.to_hash.keys.each { |k|
       if k!="cef_deviceVendor" and k!="cef_deviceProduct" and k!="cef_deviceEventClassId" and k!="cef_name" and k!="cef_severity" and k.start_with?(@cefprefix)
          unless event.get(k).nil?
             temp_val = event.get(k).gsub("=","\\=").gsub("|","\\|").gsub("\\","\\\\").gsub("\n","\\n").gsub("\r","\\r")
             temp_key = k[4..-1]
             cef_output = "#{cef_output}#{temp_key}=#{temp_val} "
          end
       end
    }
    cef_output = "#{cef_output}\r\n"
    # Add to the JSON the combined cef
    event.set("cef_output", cef_output)
    @codec.encode(event)
  end # def receive
 
end # class LogStash::Outputs::Cefgen
