#include <iostream>
#include <exception>
#include "ReplServer.h"

const time_t secs_between_repl = 20;
const unsigned int max_servers = 10;

/*********************************************************************************************
 * ReplServer (constructor) - creates our ReplServer. Initializes:
 *
 *    verbosity - passes this value into QueueMgr and local, plus each connection
 *    _time_mult - how fast to run the simulation - 2.0 = 2x faster
 *    ip_addr - which ip address to bind the server to
 *    port - bind the server here
 *
 *********************************************************************************************/
ReplServer::ReplServer(DronePlotDB &plotdb, float time_mult)
                              :_queue(1),
                               _plotdb(plotdb),
                               _shutdown(false), 
                               _time_mult(time_mult),
                               _verbosity(1),
                               _ip_addr("127.0.0.1"),
                               _port(9999)
{
}

ReplServer::ReplServer(DronePlotDB &plotdb, const char *ip_addr, unsigned short port, float time_mult,
                                          unsigned int verbosity)
                                 :_queue(verbosity),
                                  _plotdb(plotdb),
                                  _shutdown(false), 
                                  _time_mult(time_mult), 
                                  _verbosity(verbosity),
                                  _ip_addr(ip_addr),
                                  _port(port)

{
}

ReplServer::~ReplServer() {

}


/**********************************************************************************************
 * getAdjustedTime - gets the time since the replication server started up in seconds, modified
 *                   by _time_mult to speed up or slow down
 **********************************************************************************************/

time_t ReplServer::getAdjustedTime() {
   return static_cast<time_t>((time(NULL) - _start_time) * _time_mult);
}

/**********************************************************************************************
 * replicate - the main function managing replication activities. Manages the QueueMgr and reads
 *             from the queue, deconflicting entries and populating the DronePlotDB object with
 *             replicated plot points.
 *
 *    Params:  ip_addr - the local IP address to bind the listening socket
 *             port - the port to bind the listening socket
 *             
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void ReplServer::replicate(const char *ip_addr, unsigned short port) {
   _ip_addr = ip_addr;
   _port = port;
   replicate();
}

void ReplServer::replicate() {

   // Track when we started the server
   _start_time = time(NULL);
   _last_repl = 0;

   // Set up our queue's listening socket
   _queue.bindSvr(_ip_addr.c_str(), _port);
   _queue.listenSvr();

   if (_verbosity >= 2)
      std::cout << "Server bound to " << _ip_addr << ", port: " << _port << " and listening\n";

  
   // Replicate until we get the shutdown signal
   while (!_shutdown) {

      // Check for new connections, process existing connections, and populate the queue as applicable
      _queue.handleQueue();

      //sdbTimeSync();       
      //deleteDBduplicates(this->startTimeWasSet);     
  
      //deleteDBduplicates(this->startTimeWasSet);
      // See if it's time to replicate and, if so, go through the database, identifying new plots
      // that have not been replicated yet and adding them to the queue for replication
      if (getAdjustedTime() - _last_repl > secs_between_repl) {

         queueNewPlots();
         _last_repl = getAdjustedTime();
      }
        
      // Check the queue for updates and pop them until the queue is empty. The pop command only returns
      // incoming replication information--outgoing replication in the queue gets turned into a TCPConn
      // object and automatically removed from the queue by pop
      std::string sid;
      std::vector<uint8_t> data;
      while (_queue.pop(sid, data)) {
         // Incoming replication--add it to this server's local database
         addReplDronePlots(data);         
      }
      dbTimeSync2();       
      //deleteDBduplicates(this->startTimeWasSet);

      usleep(1000);
   }
   dbTimeSync2();     
   //deleteDBduplicatesFinal();   
}

/**********************************************************************************************
 * queueNewPlots - looks at the database and grabs the new plots, marshalling them and
 *                 sending them to the queue manager
 *
 *    Returns: number of new plots sent to the QueueMgr
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

unsigned int ReplServer::queueNewPlots() {
   std::vector<uint8_t> marshall_data;
   unsigned int count = 0;

   if (_verbosity >= 3)
      std::cout << "Replicating plots.\n";

   // Loop through the drone plots, looking for new ones
   std::list<DronePlot>::iterator dpit = _plotdb.begin();
   for ( ; dpit != _plotdb.end(); dpit++) {

      // If this is a new one, marshall it and clear the flag
      if (dpit->isFlagSet(DBFLAG_NEW)) {
         
         dpit->serialize(marshall_data);
         dpit->clrFlags(DBFLAG_NEW);

         count++;
      }
      if (marshall_data.size() % DronePlot::getDataSize() != 0)
         throw std::runtime_error("Issue with marshalling!");

   }
  
   if (count == 0) {
      if (_verbosity >= 3)
         std::cout << "No new plots found to replicate.\n";

      return 0;
   }
 
   // Add the count onto the front
   if (_verbosity >= 3)
      std::cout << "Adding in count: " << count << "\n";

   uint8_t *ctptr_begin = (uint8_t *) &count;
   marshall_data.insert(marshall_data.begin(), ctptr_begin, ctptr_begin+sizeof(unsigned int));

   // Send to the queue manager
   if (marshall_data.size() > 0) {
      _queue.sendToAll(marshall_data);
   }

   if (_verbosity >= 2) 
      std::cout << "Queued up " << count << " plots to be replicated.\n";

   return count;
}

/**********************************************************************************************
 * addReplDronePlots - Adds drone plots to the database from data that was replicated in. 
 *                     Deconflicts issues between plot points.
 * 
 * Params:  data - should start with the number of data points in a 32 bit unsigned integer, 
 *                 then a series of drone plot points
 *
 **********************************************************************************************/

void ReplServer::addReplDronePlots(std::vector<uint8_t> &data) {
   if (data.size() < 4) {
      throw std::runtime_error("Not enough data passed into addReplDronePlots");
   }

   if ((data.size() - 4) % DronePlot::getDataSize() != 0) {
      throw std::runtime_error("Data passed into addReplDronePlots was not the right multiple of DronePlot size");
   }

   // Get the number of plot points
   unsigned int *numptr = (unsigned int *) data.data();
   unsigned int count = *numptr;

   // Store sub-vectors for efficiency
   std::vector<uint8_t> plot;
   auto dptr = data.begin() + sizeof(unsigned int);

   for (unsigned int i=0; i<count; i++) {
      plot.clear();
      plot.assign(dptr, dptr + DronePlot::getDataSize());
      addSingleDronePlot(plot);
      dptr += DronePlot::getDataSize();      
   }
   if (_verbosity >= 2)
      std::cout << "Replicated in " << count << " plots\n";   
}


/**********************************************************************************************
 * addSingleDronePlot - Takes in binary serialized drone data and adds it to the database. 
 *
 **********************************************************************************************/

void ReplServer::addSingleDronePlot(std::vector<uint8_t> &data) {
   DronePlot tmp_plot;

   tmp_plot.deserialize(data);
   std::cout << "Adding DID: " << tmp_plot.drone_id << " NID: "  << tmp_plot.node_id << " TS: " << tmp_plot.timestamp << " LAT: "  << tmp_plot.latitude << " LONG: "  << tmp_plot.longitude << std::endl;

   _plotdb.addPlot(tmp_plot.drone_id, tmp_plot.node_id, tmp_plot.timestamp, tmp_plot.latitude,
                                                         tmp_plot.longitude);
}

void ReplServer::dbTimeSync2(){
   _plotdb.sortByTime();

   std::vector<int> foundTracking(static_cast<int>(_plotdb.size()), 0);

   int overallReferenceTime = 0;

   bool refTimeSet = false;
   if (startTimeWasSet){
      overallReferenceTime = this->masterStartTime;
      refTimeSet = true;
   }

   for (unsigned int i = 0; i < _plotdb.size(); i++)
   {
      std::vector<std::list<DronePlot>::iterator> duplicatePts;
      std::list<DronePlot>::iterator it = getDBIterator(i);


      if (!it->isFlagSet(DBFLAG_NEW))
      {      
 
         if ( it->checked ){
            continue;
         }
         else{
            duplicatePts.push_back(it);
            it->checked = true;
         }
         

         for (unsigned int j = i + 1; j < _plotdb.size(); j++)
         {
            std::list<DronePlot>::iterator it2 = getDBIterator(j);
            
            if(!it->isFlagSet(DBFLAG_NEW))
            {
               if ((it->drone_id == it2->drone_id) && (it->node_id != it2->node_id))
               {
                  if (it->latitude == it2->latitude && it->longitude == it2->longitude)
                  {
                     int tDiff = abs(it->timestamp - it2->timestamp);
                     if (tDiff < 11)
                     {
                        if (it2 != _plotdb.end()){
                           duplicatePts.push_back(it2);
                           it2->checked = true;
                        }
                        
                     }
                  }
               }
            }
         }


         int largestTime = 0;
         unsigned int tempMasterClockNode = 0;
         //finds largest timestamp for all duplicate pts
         for (unsigned int k = 0; k < duplicatePts.size(); k++)
         {
            if ( largestTime < duplicatePts.at(k)->timestamp )
            {
               largestTime = duplicatePts.at(k)->timestamp;
            }
         }

         //make sure smaller time nodes can never be the masterclock
         for (unsigned int k = 0; k < duplicatePts.size(); k++)
         {
            if ( largestTime != duplicatePts.at(k)->timestamp )
            {
               setStartTimeErrorCheckFlag(duplicatePts.at(k)->node_id);  
            }
         }

         //check/set MasterStartTime
         for (unsigned int k = 0; k < duplicatePts.size(); k++)
         {
            bool validCheck = startTimeCalcErrorCheck(duplicatePts.at(k)->node_id);
            if (validCheck){
               int tempStartTime = checkStartTimeRef(duplicatePts.at(k)->timestamp);
               if (this->masterStartTime < tempStartTime){
                  this->masterStartTime = tempStartTime;
                  this->masterClockNode = duplicatePts.at(k)->node_id;
                  this->startTimeWasSet = true;
               }
            }
         }

         if (refTimeSet){
            if (largestTime > (overallReferenceTime + 13)){
               //overallReferenceTime  += 20;
               //when svr3 (-3) & svr2 (+3) & svr1 (0)
               overallReferenceTime  += 6;
               //when svr3 (-2) && svr2 (2) & svr1 (0)
               //overallReferenceTime  += ;

            }
            else if (largestTime != overallReferenceTime){
               largestTime = overallReferenceTime;
            }
         }

         for (unsigned int m = 0; m < duplicatePts.size(); m++)
         {
            if ( largestTime != duplicatePts.at(m)->timestamp )
            {
               duplicatePts.at(m)->timestamp = largestTime;
            }  
         }

         overallReferenceTime +=5;
      }
   }

   for (unsigned int p = 0; p < _plotdb.size(); p++)
   {
      std::list<DronePlot>::iterator it = getDBIterator(p);
      it->checked = false;
   }
}


void ReplServer::syncDroneTimeSteps(int nodeId){


}


bool ReplServer::startTimeCalcErrorCheck(int nodeId){
   switch(nodeId)
   {
      case 1:
         return node1StartTimeFlag;
         break;

      case 2:
         return node2StartTimeFlag;
         break;

      default:
         return node3StartTimeFlag;
         break;
   }   

}

void ReplServer::setStartTimeErrorCheckFlag(int nodeId){
   switch(nodeId)
   {
      case 1:
         node1StartTimeFlag = false;
         break;

      case 2:
         node2StartTimeFlag = false;
         break;

      default:
         node3StartTimeFlag = false;
         break;
   }
}

void ReplServer::dbTimeSync(){
   //std::cout << "######IN DB SYNC#######" << std::endl;
   _plotdb.sortByTime();

   int referenceTime = 0;
   bool refTimeSet = false;
   if (startTimeWasSet || tempStartTimeSet){
      referenceTime = setStartTime;
      refTimeSet = false;
   }

   for (unsigned int i = 0; i < _plotdb.size(); i++){
      std::vector<std::list<DronePlot>::iterator> comparePts;
      std::list<DronePlot>::iterator it = getDBIterator(i);
      comparePts.push_back(it);
      //std::cout << "starting i: " << i << std::endl;
      //std::cout << "Pt1 DID: " << it->drone_id << " NID: "  << it->node_id << " TS: " << it->timestamp << " LAT: "  << it->latitude << " LONG: "  << it->longitude << std::endl;

      for (unsigned int j = i + 1; j < _plotdb.size(); j++){
         std::list<DronePlot>::iterator it2 = getDBIterator(j);
         //std::cout << "Pt2 DID: " << it2->drone_id << " NID: "  << it2->node_id << " TS: " << it2->timestamp << " LAT: "  << it2->latitude << " LONG: "  << it2->longitude << std::endl;
         //unsigned int tDiff = it->timestamp - it2->timestamp;

         if ((it->drone_id == it2->drone_id))
         {
            
            if (it->latitude == it2->latitude && it->longitude == it2->longitude)
            {
               //std::cout << "found same pts" << std::endl;
               if (it->node_id != it2->node_id){
                  comparePts.push_back(it2);
               

                  //if this is the last elenment in the database endloop
                  //otherwise keep looking for duplicates
                  if (j != _plotdb.size()-1){
                  //if (j != _plotdb.size()){
                     continue;
                  }
               }
            }

               if (it->timestamp > 10 && it->timestamp < 25 && ((debugFlag3 % 120) == 0) && (getAdjustedTime() < 120 ))
                  std::cout << "Same Pts:" << std::endl;

               int largestTime = 0;
               unsigned int tempMasterClockNode = 0;
               //finds the largest time/node
               for (unsigned int k = 0; k < comparePts.size(); k++)
               {
                  if ( largestTime < comparePts.at(k)->timestamp )
                  {
                     largestTime = comparePts.at(k)->timestamp;
                     tempMasterClockNode = comparePts.at(k)->node_id;

                  }
                  if (it->timestamp > 10 && it->timestamp < 25 && ((debugFlag3 % 120) == 0) && (getAdjustedTime() < 120 )){
                     std::cout << "File DID: " << comparePts.at(k)->drone_id << " NID: "  << comparePts.at(k)->node_id << " TS: " << comparePts.at(k)->timestamp << " LAT: "  << comparePts.at(k)->latitude << " LONG: "  << comparePts.at(k)->longitude << std::endl;
                  }
                  debugFlag3++;
                  if (debugFlag3 > 100000000)
                     debugFlag3 = 0;
               }

               //finds master clock
               if (comparePts.size() == 3){
                  if (masterClockNode != tempMasterClockNode){
                     masterClockNode = tempMasterClockNode;
                     std::cout << "New masterClock: " << masterClockNode << std::endl;
                  }
                  if (referenceTime == 0){
                     referenceTime = largestTime;
                     refTimeSet = true;
                     if (!startTimeWasSet)
                     {
                        setStartTimeRef(referenceTime);
                        startTimeWasSet = true;
                     }
                  }
               }
               else{
                  if (!startTimeWasSet){
                     int tempST = checkStartTimeRef(largestTime);
                     if (it->timestamp > 30 && it->timestamp < 50 && ((debugFlag3 % 120) == 0) && (getAdjustedTime() < 120 )){
                           std::cout << "StartTime: " << setStartTime << ", tempSt: " << tempST << std::endl; 
                     }
                     if (this->setStartTime < tempST){
                        this->setStartTime = tempST;
                        this->tempStartTimeSet = true;
                     }
                  }
               }

               //tires to find offsets
               for (unsigned int k = 0; k < comparePts.size(); k++)
               {
                  if (tempMasterClockNode != comparePts.at(k)->node_id){
                     int caseResult = findOffsetCase(tempMasterClockNode, comparePts.at(k)->node_id);
                     int tmpOffset = returnCaseOffset(caseResult);
                     
                     int calcOffset = largestTime - comparePts.at(k)->timestamp;

                     if (tmpOffset < calcOffset){
                        adjustCaseOffset(caseResult, calcOffset);
                     }

                  } 
               }

               //bool referenceReset = false;
               //sets time to largest clock
               for (unsigned int k = 0; k < comparePts.size(); k++)
               {
                  if (refTimeSet)
                  {
                     /*Before 769 Bug
                     if (largestTime < referenceTime){
                        std::cout << "Largest Time: " << largestTime << std::endl;
                        std::cout << "Ref Time: " << largestTime << std::endl;
                        largestTime = referenceTime;
                     }
                     else if (largestTime > (referenceTime + 15)){
                        //std::cout << "Largest Time: " << largestTime << std::endl;
                        //std::cout << "Ref Time: " << largestTime << std::endl;
                        referenceTime = largestTime;
                     }*/

                     //After 769 bug //comment out 1st if to adjust for 415 bug
                     
                     if (largestTime > (referenceTime + 15)){
                        if (debugFlag1 < 2){
                           std::cout << "In major Time diff (+15): " << largestTime << std::endl;
                           std::cout << "Largest Time: " << largestTime << std::endl;
                           std::cout << "Ref Time: " << referenceTime << std::endl;
                           std::cout << "Trigger DID: " << comparePts.at(k)->drone_id << " NID: "  << comparePts.at(k)->node_id << " TS: " << comparePts.at(k)->timestamp << " LAT: "  << comparePts.at(k)->latitude << " LONG: "  << comparePts.at(k)->longitude << std::endl;
                        }
                        //referenceReset = true;
                        referenceTime += 20;
                        if (debugFlag1 < 2){
                           std::cout << "New Ref Time: " << referenceTime << std::endl;
                           debugFlag1++;
                        }
                     }
                     else if (largestTime != referenceTime){//*/
                     //if (largestTime != referenceTime){ //removes 415 bug
                        if (debugFlag2 < 2){
                           std::cout << "Largest2 Time: " << largestTime << std::endl;
                           std::cout << "Ref2 Time: " << referenceTime << std::endl;
                           std::cout << "Trigger DID: " << comparePts.at(k)->drone_id << " NID: "  << comparePts.at(k)->node_id << " TS: " << comparePts.at(k)->timestamp << " LAT: "  << comparePts.at(k)->latitude << " LONG: "  << comparePts.at(k)->longitude << std::endl;
                           debugFlag2++;
                        }
                        largestTime = referenceTime;
                     }
                     
                  }
                  if ( largestTime != comparePts.at(k)->timestamp )
                  {
                     std::cout << "Orig DID: " << comparePts.at(k)->drone_id << " NID: "  << comparePts.at(k)->node_id << " TS: " << comparePts.at(k)->timestamp << " LAT: "  << comparePts.at(k)->latitude << " LONG: "  << comparePts.at(k)->longitude << std::endl;
                     std::cout << "Changing Time Stamp to: "<< largestTime << std::endl;
                     comparePts.at(k)->timestamp = largestTime;
                     comparePts.at(k)->adjusted = true;
                  }
                  //std::cout << "File DID: " << comparePts.at(k)->drone_id << " NID: "  << comparePts.at(k)->node_id << " TS: " << comparePts.at(k)->timestamp << " LAT: "  << comparePts.at(k)->latitude << " LONG: "  << comparePts.at(k)->longitude << std::endl;
                  //comparePts.at(k)->setFlags(DBFLAG_USER1);
                  
               }

               i = j-1;
               //if (!referenceReset){
                  referenceTime += 5;
               //}
               //std::cout << "new i: " << i << std::endl;
               break;
         }
      }
   }

}

void ReplServer::deleteDBduplicates(bool StartTimeFlag){
   _plotdb.sortByTime();

   std::vector<int> duplicateIndex;

   if (StartTimeFlag || (cycles > 99) ){
      for (unsigned int i = 0; i < _plotdb.size(); i++)
      {
         std::vector<std::list<DronePlot>::iterator> duplicatePts;
         std::list<DronePlot>::iterator it = getDBIterator(i);


         if (!it->isFlagSet(DBFLAG_NEW))
         {
            
            for (unsigned int j = i + 1; j < _plotdb.size(); j++)
            {
               std::list<DronePlot>::iterator it2 = getDBIterator(j);
               
               if(!it->isFlagSet(DBFLAG_NEW))
               {
                  if ((it->drone_id == it2->drone_id))
                  {
                     if (it->latitude == it2->latitude && it->longitude == it2->longitude)
                     {
                        int tDiff = abs(it->timestamp - it2->timestamp);
                        if (tDiff < 7)
                        {
                           bool checkFound = checkIfAlreadyFound(duplicateIndex, j);
                           if (!checkFound){
                              duplicateIndex.push_back(j);
                           }
                        }
                     }
                  }
               }
            }
         }     
      }

      while (!duplicateIndex.empty())
      {
         std::list<DronePlot>::iterator it = getDBIterator(duplicateIndex.at(duplicateIndex.size()-1));
         std::cout << "Deleting DID: " << it->drone_id << " NID: "  << it->node_id << " TS: " << it->timestamp << " LAT: "  << it->latitude << " LONG: "  << it->longitude << std::endl;
         //std::cout << "deleting INDEX pts" << std::endl;
         //std::cout << "size of vector : " << duplicateIndex.size() << std::endl;
         //std::cout << "delteing (at) index: " << duplicateIndex.size() - 1 << std::endl;
         //std::cout << "delteing deref: " << duplicateIndex.at(duplicateIndex.size()-1) << std::endl;
         _plotdb.erase(duplicateIndex.at(duplicateIndex.size()-1));
         
         duplicateIndex.pop_back();
      }
   }
   this->cycles++;
   

/*
   if (this->cycles > 100 || StartTimeFlag){
  //if (StartTimeFlag && (this->cycles > 100)){
      
      std::vector<int> duplicateIndex;
      //int index1 = 0;
      for (unsigned int i = 0; i < _plotdb.size(); i++)
      {
         std::list<DronePlot>::iterator it = getDBIterator(i);

         for(unsigned int j = i+1; j < _plotdb.size(); j++)
         {
            std::list<DronePlot>::iterator it2 = getDBIterator(j);
            if ( (it->drone_id == it2->drone_id) && (it->latitude == it2->latitude) && (it->longitude == it2->longitude) && (it->timestamp == it2->timestamp))
            {
               //if (it2->adjusted){
                  std::cout << "In duplicate delete Funct, duplicateFound" << std::endl;
                  duplicateIndex.push_back(j);
               //}
            }
            else{
               i = j - 1;
               break;
            }
         }
      }


      while (!duplicateIndex.empty())
      {
         std::list<DronePlot>::iterator it = getDBIterator(duplicateIndex.at(duplicateIndex.size()-1));
         std::cout << "Deleting DID: " << it->drone_id << " NID: "  << it->node_id << " TS: " << it->timestamp << " LAT: "  << it->latitude << " LONG: "  << it->longitude << std::endl;
         //std::cout << "deleting INDEX pts" << std::endl;
         //std::cout << "size of vector : " << duplicateIndex.size() << std::endl;
         //std::cout << "delteing (at) index: " << duplicateIndex.size() - 1 << std::endl;
         //std::cout << "delteing deref: " << duplicateIndex.at(duplicateIndex.size()-1) << std::endl;
         _plotdb.erase(duplicateIndex.at(duplicateIndex.size()-1));
         
         duplicateIndex.pop_back();
      }
   }
   this->cycles++;
*/

}

bool ReplServer::checkIfAlreadyFound(std::vector<int> inputVector, int value){
   for(auto v : inputVector){
      if (v == value){
         return true;
      }
   }

   return false;

}


void ReplServer::deleteDBduplicatesFinal(){
   _plotdb.sortByTime();

   //if (StartTimeFlag || (this->cycles > 10)){
   //if (StartTimeFlag && (this->cycles > 100)){
      std::vector<int> duplicateIndex;
      //int index1 = 0;
      for (unsigned int i = 0; i < _plotdb.size(); i++)
      {
         std::list<DronePlot>::iterator it = getDBIterator(i);

         for(unsigned int j = i+1; j < _plotdb.size(); j++)
         {
            std::list<DronePlot>::iterator it2 = getDBIterator(j);
            if ( (it->drone_id == it2->drone_id) && (it->latitude == it2->latitude) && (it->longitude == it2->longitude) && (it->timestamp == it2->timestamp))
            {
               //if (it2->isFlagSet(DBFLAG_USER1)){
                  duplicateIndex.push_back(j);
               //}
            }
            else{
               i = j - 1;
               break;
            }
         }
      }


      while (!duplicateIndex.empty())
      {
         std::list<DronePlot>::iterator it = getDBIterator(duplicateIndex.at(duplicateIndex.size()-1));
         std::cout << "Deleting DID: " << it->drone_id << " NID: "  << it->node_id << " TS: " << it->timestamp << " LAT: "  << it->latitude << " LONG: "  << it->longitude << std::endl;
         //std::cout << "deleting INDEX pts" << std::endl;
         //std::cout << "size of vector : " << duplicateIndex.size() << std::endl;
         //std::cout << "delteing (at) index: " << duplicateIndex.size() - 1 << std::endl;
         //std::cout << "delteing deref: " << duplicateIndex.at(duplicateIndex.size()-1) << std::endl;
         _plotdb.erase(duplicateIndex.at(duplicateIndex.size()-1));
         
         duplicateIndex.pop_back();
      }
   //}
}

std::list<DronePlot>::iterator ReplServer::getDBIterator(unsigned int index){
   std::list<DronePlot>::iterator retIt;
   retIt = _plotdb.begin();
   for (unsigned int i = 0; i < _plotdb.size(); i++){
      if (index == i){
         return retIt;
      }
      retIt = std::next(retIt);
   }

   return _plotdb.end();
}

int ReplServer::findOffsetCase(unsigned int Node1, unsigned int Node2){
   if (Node1 == 1 || Node2 == 1)
   {
      if (Node1 == 2 || Node2 == 2)
      {
         //case 1: offset12
         return 1;
      }
      else
      {
         //case 2: ofset13
         return 2;
      }
   }
   else{
      //case 3: ofset23
      return 3;
   }
}

void ReplServer::adjustCaseOffset(int inputCase, int inputOffset){
   switch(inputCase)
   {
      case 1:
         masterOffset12 = inputOffset;
         break;

      case 2:
         masterOffset13 = inputOffset;
         break;

      default:
         masterOffset23 = inputOffset;
         break;
   }
}

void ReplServer::setStartTimeRef(int referenceTime){
   this->storedRefTime = referenceTime;
   int tempNum = referenceTime;
   while (tempNum > 8){
      tempNum -= 5;
   }
   this->setStartTime = tempNum;
   std::cout << "#######################START TIME SET ########################" << std::endl;
}

int ReplServer::checkStartTimeRef(int referenceTime){
   int tempNum = referenceTime;
   while (tempNum > 8){
      tempNum -= 5;
   }
   return tempNum;
}


int ReplServer::returnCaseOffset(int inputCase){
   switch(inputCase)
   {
      case 1:
         return masterOffset12;
         break;

      case 2:
         return masterOffset13;
         break;

      default:
         return masterOffset23;
         break;
   }
}

void ReplServer::shutdown() {
   //dbTimeSync();
   //deleteDBduplicatesFinal();

   std::cout << "Calc Start Time: " << this->masterStartTime << std::endl;
   std::cout << "MasterClock: " << masterClockNode << std::endl;
   std::cout << "offset 12: " << masterOffset12 << std::endl;
   std::cout << "offset 23: " << masterOffset23 << std::endl;
   std::cout << "offset 13: " << masterOffset13 << std::endl;   

   _shutdown = true;

}
