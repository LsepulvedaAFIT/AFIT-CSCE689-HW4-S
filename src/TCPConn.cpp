#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sstream>
#include "TCPConn.h"
#include "strfuncts.h"
#include <crypto++/secblock.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/rijndael.h>
#include <crypto++/gcm.h>
#include <crypto++/aes.h>

#include <iterator>

using namespace CryptoPP;

// Common defines for this TCPConn
const unsigned int iv_size = AES::BLOCKSIZE;
const unsigned int key_size = AES::DEFAULT_KEYLENGTH;
const unsigned int auth_size = 16;

/**********************************************************************************************
 * TCPConn (constructor) - creates the connector and initializes - creates the command strings
 *                         to wrap around network commands
 *
 *    Params: key - reference to the pre-loaded AES key
 *            verbosity - stdout verbosity - 3 = max
 *
 **********************************************************************************************/

TCPConn::TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity):
                                    _data_ready(false),
                                    _aes_key(key),
                                    _verbosity(verbosity),
                                    _server_log(server_log)
{
   // prep some tools to search for command sequences in data
   uint8_t slash = (uint8_t) '/';
   c_rep.push_back((uint8_t) '<');
   c_rep.push_back((uint8_t) 'R');
   c_rep.push_back((uint8_t) 'E');
   c_rep.push_back((uint8_t) 'P');
   c_rep.push_back((uint8_t) '>');

   c_endrep = c_rep;
   c_endrep.insert(c_endrep.begin()+1, 1, slash);

   c_ack.push_back((uint8_t) '<');
   c_ack.push_back((uint8_t) 'A');
   c_ack.push_back((uint8_t) 'C');
   c_ack.push_back((uint8_t) 'K');
   c_ack.push_back((uint8_t) '>');

   c_auth.push_back((uint8_t) '<');
   c_auth.push_back((uint8_t) 'A');
   c_auth.push_back((uint8_t) 'U');
   c_auth.push_back((uint8_t) 'T');
   c_auth.push_back((uint8_t) '>');

   c_endauth = c_auth;
   c_endauth.insert(c_endauth.begin()+1, 1, slash);

   c_sid.push_back((uint8_t) '<');
   c_sid.push_back((uint8_t) 'S');
   c_sid.push_back((uint8_t) 'I');
   c_sid.push_back((uint8_t) 'D');
   c_sid.push_back((uint8_t) '>');

   c_endsid = c_sid;
   c_endsid.insert(c_endsid.begin()+1, 1, slash);
}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   //std::cout << "In accept() " << std::endl;
   // Accept the connection
   bool results = _connfd.acceptFD(server);


   // Set the state as waiting for the authorization packet
   _status = s_connected;
   _connected = true;
   return results;
}

/**********************************************************************************************
 * sendData - sends the data in the parameter to the socket
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendData(std::vector<uint8_t> &buf) {
   
   _connfd.writeBytes<uint8_t>(buf);
   
   return true;
}

/**********************************************************************************************
 * sendEncryptedData - sends the data in the parameter to the socket after block encrypting it
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendEncryptedData(std::vector<uint8_t> &buf) {

   // Encrypt
   encryptData(buf);

   // And send!
   return sendData(buf);
}

/**********************************************************************************************
 * encryptData - block encrypts data and places the results in the buffer in <ID><Data> format
 *
 *    Params:  buf - where to place the <IV><Data> stream
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

void TCPConn::encryptData(std::vector<uint8_t> &buf) {
   // For the initialization vector
   SecByteBlock init_vector(iv_size);
   AutoSeededRandomPool rnd;

   // Generate our random init vector
   rnd.GenerateBlock(init_vector, init_vector.size());

   // Encrypt the data
   CFB_Mode<AES>::Encryption encryptor;
   encryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   std::string cipher;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(encryptor, new StringSink(cipher)));

   // Now add the IV to the stream we will be sending out
   std::vector<uint8_t> enc_data(init_vector.begin(), init_vector.end());
   enc_data.insert(enc_data.end(), cipher.begin(), cipher.end());
   buf = enc_data;
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   try {
      switch (_status) {

         // Client: Just connected, send our SID
         case s_connecting:
            //std::cout << "In s_connecting state"<<std::endl;
            sendSID();
            break;

         // Server: Wait for the SID from a newly-connected client, then send our SID
         case s_connected:
            //std::cout << "In s_connected state"<<std::endl;
            waitForSID();
            break;

         // Server: Send the authentication string in clear text
         case s_svrSendAuthString:
            //std::cout << "In s_svrSendAuthString state"<<std::endl;
            svrSendAuth();
            //sendAuthenticationString();
            break;

         //Client: wait for Auth String and send response
         case s_clientAuthResp:
            //std::cout << "In s_clientAuthResp state"<<std::endl;
            clientAuthProcess();
            break;

         //Server: Waits for client to send encrypted string
         // and clear text authentication string 
         case s_svrWaitForResp:
            //std::cout << "In s_svrWaitForResp state"<<std::endl;
            svrAuthRespProcess();
            break;

         //Server: Returns encrypted Authentication string
         case s_svrSendAuthResp:
            //std::cout << "In s_svrSendAuthResp state"<<std::endl;
            svrAuthSendProcess();
            break;

         //Client: final check of encryption reply from server
         case s_cFinalCheck:
            //std::cout << "s_cFinalCheck" <<std::endl;//testing
            finalAuthCheck();
            break;
   
         // Client: connecting user - replicate data
         case s_datatx:
            //std::cout << "In s_datatx state"<<std::endl;//testing   
            transmitData();
            break;

         // Server: Receive data from the client
         case s_datarx:
            //std::cout << "In s_datarx state"<<std::endl;//testing
            waitForData();
            break;
   
         // Client: Wait for acknowledgement that data sent was received before disconnecting
         case s_waitack:
            std::cout << "In s_waitack state"<<std::endl;
            awaitAck();
            break;
         
         // Server: Data received and conn disconnected, but waiting for the data to be retrieved
         case s_hasdata:
            std::cout << "In s_hasData state"<<std::endl;
            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.\n";
      disconnect();
      return;
   }

}

/**********************************************************************************************
 * sendSID()  - Client: after a connection, client sends its Server ID to the server
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::sendSID() {
   std::vector<uint8_t> buf(_svr_id.begin(), _svr_id.end());
   wrapCmd(buf, c_sid, c_endsid);
   sendData(buf);

   //_status = s_datatx; 
   _status = s_clientAuthResp;
}

/**********************************************************************************************
 * waitForSID()  - receives the SID and sends our SID
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::waitForSID() {

   // If data on the socket, should be our Auth string from our host server
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (!getCmdData(buf, c_sid, c_endsid)) {
         std::stringstream msg;
         msg << "SID string from connecting client invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      std::string node(buf.begin(), buf.end());
      setNodeID(node.c_str());
      std::cout << "Server, SID recieved: " << node << std::endl;

      // Send our Node ID
      //buf.assign(_svr_id.begin(), _svr_id.end());
      //wrapCmd(buf, c_sid, c_endsid);
      //sendData(buf);

      //_status = s_datarx;
      _status = s_svrSendAuthString;
   }
}


/**********************************************************************************************
 * transmitData()  - transmits encrypted data
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::transmitData() {
   //std::cout << "In transitData()" << std::endl;

   //encrypts data
   encryptData(_outputbuf);
   // Send the replication data
   sendData(_outputbuf);

   if (_verbosity >= 3)
      std::cout << "Successfully authenticated connection with " << getNodeID() <<
                   " and sending replication data.\n";

   // Wait for their response
   _status = s_waitack;

}


/**********************************************************************************************
 * waitForData - receiving server, authentication complete, wait for replication datai
               Also sends a plaintext random auth string of our own
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::waitForData() {

   // If data on the socket, should be replication data
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      decryptData(buf);

      if (!getCmdData(buf, c_rep, c_endrep)) {
         std::stringstream msg;
         msg << "Replication data possibly corrupted from" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      // Got the data, save it
      _inputbuf = buf;
      _data_ready = true;

      // Send the acknowledgement and disconnect
      encryptData(c_ack);
      sendData(c_ack);

      if (_verbosity >= 2)
         std::cout << "Successfully received replication data from " << getNodeID() << "\n";


      disconnect();
      _status = s_hasdata;
   }
}


/**********************************************************************************************
 * awaitAwk - waits for the awk that data was received and disconnects
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::awaitAck() {
   //std::cout << "In Awaiting ACK.\n";

   // Should have the awk message
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;
      //std::cout << "In Awaiting ACK Data.\n";

      if (!getData(buf))
         return;
      
      decryptData(buf);

      if (findCmd(buf, c_ack) == buf.end())
      {
         std::stringstream msg;
         msg << "Awk expected from data send, received something else. Node:" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
      }
  
      if (_verbosity >= 3)
         std::cout << "Data ack received from " << getNodeID() << ". Disconnecting.\n";

 
      disconnect();
   }
}

/**********************************************************************************************
 * getData - Reads in data from the socket and checks to see if there's an end command to the
 *           message to confirm we got it all
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false if they lost connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getData(std::vector<uint8_t> &buf) {

   std::vector<uint8_t> readbuf;
   size_t count = 0;

   buf.clear();

   while (_connfd.hasData()) {
      // read the data on the socket up to 1024
      count += _connfd.readBytes<uint8_t>(readbuf, 1024);

      // check if we lost connection
      if (readbuf.size() == 0) {
         std::stringstream msg;
         std::string ip_addr;
         msg << "Connection from server " << _node_id << " lost (IP: " << 
                                                         getIPAddrStr(ip_addr) << ")"; 
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return false;
      }

      buf.insert(buf.end(), readbuf.begin(), readbuf.end());

      // concat the data onto anything we've read before
//      _inputbuf.insert(_inputbuf.end(), readbuf.begin(), readbuf.end());
   }
   return true;
}

/**********************************************************************************************
 * decryptData - Takes in an encrypted buffer in the form IV/Data and decrypts it, replacing
 *               buf with the decrypted info (destroys IV string>
 *
 *    Params: buf - the encrypted string and holds the decrypted data (minus IV)
 *
 **********************************************************************************************/
void TCPConn::decryptData(std::vector<uint8_t> &buf) {
   // For the initialization vector
   SecByteBlock init_vector(iv_size);

   // Copy the IV from the incoming stream of data
   init_vector.Assign(buf.data(), iv_size);
   buf.erase(buf.begin(), buf.begin() + iv_size);

   // Decrypt the data
   CFB_Mode<AES>::Decryption decryptor;
   decryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   std::string recovered;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(decryptor, new StringSink(recovered)));

   buf.assign(recovered.begin(), recovered.end());

}


/**********************************************************************************************
 * getEncryptedData - Reads in data from the socket and decrypts it, passing the decrypted
 *                    data back in buf
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false otherwise
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getEncryptedData(std::vector<uint8_t> &buf) {
   // Get the data from the socket
   if (!getData(buf))
      return false;

   decryptData(buf);

   return true; 
}

/**********************************************************************************************
 * findCmd - returns an iterator to the location of a string where a command starts
 * hasCmd - returns true if command was found, false otherwise
 *
 *    Params: buf = the data buffer to look for the command within
 *            cmd - the command string to search for in the data
 *
 *    Returns: iterator - points to cmd position if found, end() if not found
 *
 **********************************************************************************************/

std::vector<uint8_t>::iterator TCPConn::findCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return std::search(buf.begin(), buf.end(), cmd.begin(), cmd.end());
}

bool TCPConn::hasCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return !(findCmd(buf, cmd) == buf.end());
}

/**********************************************************************************************
 * getCmdData - looks for a startcmd and endcmd and returns the data between the two 
 *
 *    Params: buf = the string to search for the tags
 *            startcmd - the command at the beginning of the data sought
 *            endcmd - the command at the end of the data sought
 *
 *    Returns: true if both start and end commands were found, false otherwisei
 *
 **********************************************************************************************/

bool TCPConn::getCmdData(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, 
                                                    std::vector<uint8_t> &endcmd) {
   std::vector<uint8_t> temp = buf;
   auto start = findCmd(temp, startcmd);
   auto end = findCmd(temp, endcmd);

   if ((start == temp.end()) || (end == temp.end()))
      return false;

   buf.assign(start + startcmd.size(), end);
   return true;
}

/**********************************************************************************************
 * wrapCmd - wraps the command brackets around the passed-in data
 *
 *    Params: buf = the string to wrap around
 *            startcmd - the command at the beginning of the data
 *            endcmd - the command at the end of the data
 *
 **********************************************************************************************/

void TCPConn::wrapCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd,
                                                    std::vector<uint8_t> &endcmd) {
   std::vector<uint8_t> temp = startcmd;
   temp.insert(temp.end(), buf.begin(), buf.end());
   temp.insert(temp.end(), endcmd.begin(), endcmd.end());

   buf = temp;
}


/**********************************************************************************************
 * getReplData - Returns the data received on the socket and marks the socket as done
 *
 *    Params: buf = the data received
 *
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getInputData(std::vector<uint8_t> &buf) {

   // Returns the replication data off this connection, then prepares it to be removed
   buf = _inputbuf;

   _data_ready = false;
   _status = s_none;
}

/**********************************************************************************************
 * connect - Opens the socket FD, attempting to connect to the remote server
 *
 *    Params:  ip_addr - ip address string to connect to
 *             port - port in host format to connect to
 *
 *    Throws: socket_error exception if failed. socket_error is a child class of runtime_error
 **********************************************************************************************/

void TCPConn::connect(const char *ip_addr, unsigned short port) {
   //std::cout << "In connect() " << std::endl;

   // Set the status to connecting
   _status = s_connecting;

   // Try to connect
   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

// Same as above, but ip_addr and port are in network (big endian) format
void TCPConn::connect(unsigned long ip_addr, unsigned short port) {
   //std::cout << "In connect() " << std::endl;
   // Set the status to connecting
   _status = s_connecting;

   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

/**********************************************************************************************
 * assignOutgoingData - sets up the connection so that, at the next handleConnection, the data
 *                      is sent to the target server
 *
 *    Params:  data - the data stream to send to the server
 *
 **********************************************************************************************/

void TCPConn::assignOutgoingData(std::vector<uint8_t> &data) {

   _outputbuf.clear();
   _outputbuf = c_rep;
   _outputbuf.insert(_outputbuf.end(), data.begin(), data.end());
   _outputbuf.insert(_outputbuf.end(), c_endrep.begin(), c_endrep.end());
}
 

/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
   _connected = false;
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connected;
   // return _connfd.isOpen(); // This does not work very well
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
const char *TCPConn::getIPAddrStr(std::string &buf) {
   _connfd.getIPAddrStr(buf);
   return buf.c_str();
}

/**********************************************************************************************
 * sendAuthenticationString - send an clear text authentication string in support of encryption 
 * process shown in figure 9.6 of the text book
 * 
 **********************************************************************************************/

void TCPConn::sendAuthenticationString() {
   //testing
   //std::cout << "In sendAuthenticationString()" << std::endl;
   
   // If data on the socket, should be our Auth string from our host server
   std::vector<uint8_t> buf;
   std::vector<uint8_t> buf2;  
      
   //Generating number and stores it for later comparison
   authString.clear();

   //creates a random number to send as an authentication string
   for (int i = 0; i < 12; i++){
      int randomNum = rand() % 30;
      buf.push_back(randomNum);
      //stores it for later comparison
      authString.push_back(randomNum);
   }
   
   //Testing
   /*
   std::stringstream result;
   std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(result, " "));
   std::cout << "Sending Auth: "<< result.str() << std::endl;*/
   
   //sends clear text authentication string
   wrapCmd(buf, c_auth, c_endauth);
   bool sendResult = sendData(buf);
   if (!sendResult){
      std::cout << "Error sending message" << std::endl;
      std::cout << "Disconnecting socket to restart authentication process" << std::endl;
      std::stringstream msg;
      msg << "Sending auth string failed. disconneted to restart authentication process";
      _server_log.writeLog(msg.str().c_str());
      disconnect();
   }
   //Tesing
   //std::cout << "Size auth : "<< buf.size() << std::endl;
}

/*********************************************************************************
 * waitForAuthString - wait to recieve authentication string from server/client
 * 
 *    disconnects if data recieved was in the inproper format
 *    writes error to log file
 * ******************************************************************************/

void TCPConn::waitForAuthString(){
   //std::cout << "In waitForAuthString()AndResp" << std::endl;

   //buffer to store recieved data
   std::vector<uint8_t> buf;

   //Loops until it recieves data 
   if (!getData(buf))
      return;

   if (!getCmdData(buf, c_auth, c_endauth)) {
      std::cout << "Auth string from connecting client invalid format. Cannot authenticate" << std::endl;
      //Testing
      /*
      std::cout << "size of buff: " << buf.size() << std::endl;
      std::stringstream resulttest;
      std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(resulttest, " "));
      std::cout << "Recieved buff: "<< resulttest.str() << std::endl;*/
         
      //logs message in server
      std::stringstream msg;
      msg << "Auth string from connecting client invalid format. Cannot authenticate.";
      _server_log.writeLog(msg.str().c_str());
      disconnect();
      return;
   }

   //stores recieved string in container for later processing
   this->recAuthString = buf;

   //testing
   /*
   std::stringstream result;
   std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(result, " "));
   std::cout << "Recieved Auth: "<< result.str() << std::endl;*/

   //Testing
   /*
   std::stringstream result5;
   std::copy(this->recAuthString.begin(), this->recAuthString.end(), std::ostream_iterator<int>(result5, " "));
   std::cout << "Recieved Auth String: "<< result.str() << std::endl;*/
}

/********************************************************************************
 *  svrSendAuth - sends authentication string and transitions to new state to
 * wait for encrypted authentication response
 * 
 * *****************************************************************************/

void TCPConn::svrSendAuth(){
   sendAuthenticationString();
   _status = s_svrWaitForResp;
}

/********************************************************************************
 * clientAuthProcess  - waits to recieve clear text authenticaiton string from 
 *    server and sends it encrypted.  Transitions to final check to wait for the
 *    encryption authentication reply from the server
 * (Note: Wrapping function to reuse internal function, minimize code replication)
 * *****************************************************************************/

void TCPConn::clientAuthProcess(){
   if (_connfd.hasData()) {
      waitForAuthString();
      sendAuthenticationRespAndString();
      _status = s_cFinalCheck;
   }
}

/********************************************************************************
 * svrAuthRespProcess - waits for the encrypted reply from the client and a clear
 *    text authentication string.  Transitions to encrypt clear text authentication
 *    string return it back to the client 
 * (Note: Wrapping function to reuse internal function, minimize code replication)
 * ***************************************************************************/

void TCPConn::svrAuthRespProcess(){
   if (_connfd.hasData()) {
      waitForEncryptAuthReplyAndAuthString();
      _status = s_svrSendAuthResp;
   }
}
/*******************************************************************************
 * svrAuthSendProcess - encrypt clear text authentication string returns it 
 *    back to the client for final check before interchanging encrypted data.
 *    Transition to wait to recieve data from client
 * (Note: Wrapping function to reuse internal function, minimize code replication)
 * ***************************************************************************/
void TCPConn::svrAuthSendProcess(){
   sendAuthenticationResp();
   _status = s_datarx;
}


/******************************************************************************
 * waitForEncryptAuthReply - waits for encrypted response and checks if it 
 *    matches the string that was sent. 
 * 
 *    Disconnects if strings do not match.
 * 
 * **************************************************************************/
void TCPConn::waitForEncryptAuthReply(){
   //std::cout << "in waitForEncryptAuthReply()" << std::endl;//Testing

      //buffer to store incoming data
      std::vector<uint8_t> buf;

      //loops until data is recieves
      if (!getData(buf))
         return;

      //decrypts incoming data
      decryptData(buf);
      //std::cout << "Data decrypted" << std::endl; //Testing

      //checks if data came in the proper format
      if (!getCmdData(buf, c_auth, c_endauth)) {
         std::cout << "Error invalid format" << std::endl;
         std::stringstream msg;
         msg << "Auth string from connecting client invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      //check if replied string matches the string that was sent 
      if (buf == this->authString){
         std::cout << "TCP Connection message: authentication string matches" << std::endl;
      }
      else{
         std::cout << "TCP Connection message: Recieved authentication string DO NOT match, Disconnecting" << std::endl;
         std::stringstream msg;
         msg << "Auth string from connecting client does not match. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();

         /****TESTING*****
         std::stringstream result;
         std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(result, " "));
         std::cout << "Buf: "<< result.str() << std::endl;

         std::stringstream result2;
         std::copy(authString.begin(), authString.end(), std::ostream_iterator<int>(result, " "));
         std::cout << "AuthString: "<< result2.str() << std::endl;*/
      }
}

/**********************************************************************************
 * finalAuthCheck - perform an the final check for the client before sending data
 * 
 * Waits for the encrpted reply from server and transitions to data tranx state
 * ********************************************************************************/

void TCPConn::finalAuthCheck(){
   if (_connfd.hasData()) {
      waitForEncryptAuthReply();
      _status = s_datatx; 
   }
}

/**********************************************************************************
 * sendAuthenticationRespAndString - encrypts recieved authentication string and
 *    sends it back to the server.  Creates and new random number to send as an 
 *    authentication string for the server.
 * 
 *   Disconnects if it is unable to send data to restart the authentication 
 *       process.
 * ********************************************************************************/

void TCPConn::sendAuthenticationRespAndString() {
   //std::cout << "In sendAuthenticationRespAndString()" << std::endl;
   
   // If data on the socket, should be our Auth string from our host server
   std::vector<uint8_t> buf;
   std::vector<uint8_t> buf2;

   //recieves the data, wraps it, and encrypts it
   buf = this->recAuthString;
   wrapCmd(buf, c_auth, c_endauth);
   encryptData(buf);

   //std::cout << "size of encrypt buf: " << buf.size() << std::endl;
      
   //Containt that stores the generated string to compare at a later time   
   authString.clear();

   //Generating number and storing it in buf   
   for (int i = 0; i < 12; i++){
      int randomNum = rand() % 30;
      buf2.push_back(randomNum);
      authString.push_back(randomNum);
   }
   
   //testing
   /*
   std::stringstream result;
   std::copy(buf2.begin(), buf2.end(), std::ostream_iterator<int>(result, " "));
   std::cout << "Sending Auth: "<< result.str() << std::endl;*/
   
   //sends clear text authentication string
   wrapCmd(buf2, c_auth, c_endauth);
   buf.insert( buf.end(), buf2.begin(), buf2.end() );
   bool sendResult = sendData(buf);
   if (!sendResult){
      std::cout << "TCP Connnection message: Error sending message" << std::endl;
      std::cout << "TCP Connnection message: Disconnecting socket to restart authentication process" << std::endl;
      //writes error to log file
      std::stringstream msg;
      msg << "Sending auth string failed. disconneted to restart authentication process";
      _server_log.writeLog(msg.str().c_str());
      disconnect();
   }
   //std::cout << "Size auth : "<< buf.size() << std::endl;

   //buf2.assign(_svr_id.begin(), _svr_id.end());
   //wrapCmd(buf2, c_sid, c_endsid);
   //sendData(buf2);
}

/********************************************************************************
 * waitForEncryptAuthReplyAndAuthString - wait for the encrypted authentication
 *    string and clear text authentication string from the client
 * 
 *    Disconnect if incomming data is not properly formatted
 * *****************************************************************************/

void TCPConn::waitForEncryptAuthReplyAndAuthString(){
   //std::cout << "waitForEncryptAuthReplyAndAuthString()" << std::endl;//Testing

      std::vector<uint8_t> buf;
      std::vector<uint8_t> encrypAuthStr;

      //loops until data is recieved
      if (!getData(buf))
         return;


      //transfers incoming into buffer to parse the encrypted message from the
      std::copy(buf.begin(), buf.begin() + 62, std::back_inserter(encrypAuthStr));
      //decrypts data
      decryptData(encrypAuthStr);

      //removes the encrypted authentication string
      if (!getCmdData(encrypAuthStr, c_auth, c_endauth)) {
         std::cout << "TCP Connnection message: Error recieved data in invalid format EncrypteAuthStr" << std::endl;
         std::stringstream msg;
         msg << "Auth string from connecting client invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      //calculates the initial part of data that needs to be removed to get
      //authentication string before data is altered
      int discardSize = encrypAuthStr.size();       

      //compares recieved string to the string that was sent
      if (encrypAuthStr == this->authString){
         std::cout << "TCP Connection message: authentication string matches" << std::endl;
      }
      else{
         std::cout << "TCP Connection message: Recieved authentication string DO NOT match, Disconnecting" << std::endl;
         std::stringstream msg;
         msg << "Auth string from connecting client does not match. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();

         //Testing
         /*
         std::stringstream result;
         std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(result, " "));
         std::cout << "Buf: "<< result.str() << std::endl;

         std::stringstream result2;
         std::copy(authString.begin(), authString.end(), std::ostream_iterator<int>(result, " "));
         std::cout << "AuthString: "<< result2.str() << std::endl;*/
      }

      //discard the first part of the message to access clear text authentication string
      buf.erase(buf.begin(), buf.begin()+discardSize);


      if (!getCmdData(buf, c_auth, c_endauth)) {
         std::cout << "TCP Connnection message: Auth string from connecting client invalid format. Cannot authenticate" << std::endl;
         /*//Testing
         std::cout << "size of buff: " << buf.size() << std::endl;
         std::stringstream resulttest;
         std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(resulttest, " "));
         std::cout << "Recieved buff: "<< resulttest.str() << std::endl;*/
         
         //log error message
         std::stringstream msg;
         msg << "Auth string from connecting client invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      //Testing
      /*
      std::stringstream result;
      std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(result, " "));
      std::cout << "Recieved Auth: "<< result.str() << std::endl;*/

      //stores recieved clear text authentication string
      this->recAuthString = buf;

      //Testing
      /*
      std::stringstream result5;
      std::copy(this->recAuthString.begin(), this->recAuthString.end(), std::ostream_iterator<int>(result5, " "));
      std::cout << "Recieved Auth String: "<< result.str() << std::endl;*/

}

/*******************************************************************************************************
 * sendAuthenticationResp - encrypts the clear text authentication string by the client and sends it
 *    back to the client.
 * 
 *    Disconnects if it is unable to send data to restart the authentication 
 *       process.
 * ****************************************************************************************************/

void TCPConn::sendAuthenticationResp(){
   //std::cout << "In sendAuthenticationResp()" << std::endl;
   
   // If data on the socket, should be our Auth string from our host server
   std::vector<uint8_t> buf;
   std::vector<uint8_t> buf2;

   //load recieved authentication string into buffer
   buf = this->recAuthString;

   //Testing
   /*
   std::stringstream result;
   std::copy(buf.begin(), buf.end(), std::ostream_iterator<int>(result, " "));
   std::cout << "Sending Auth resp: "<< result.str() << std::endl;*/


   wrapCmd(buf, c_auth, c_endauth);
   encryptData(buf);


   bool sendResult = sendData(buf);
   if (!sendResult){
      std::cout << "TCP Connnection message: Error sending message" << std::endl;
      std::cout << "TCP Connnection message: Disconnecting socket to restart authentication process" << std::endl;
      //writes message to 
      std::stringstream msg;
      msg << "Sending encrypted authenticatio string failed. disconneted to restart authentication process";
      _server_log.writeLog(msg.str().c_str());
      disconnect();
   }

}