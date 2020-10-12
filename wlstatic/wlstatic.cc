/*
Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
Reserved. 

Permission to use, copy, modify, and distribute this
software and its documentation is hereby granted (including for
commercial or for-profit use), provided that both the copyright notice and this permission notice appear in all copies of the software, derivative works, or modified versions, and any portions thereof, and that both notices appear in supporting documentation, and that credit is given to Carnegie Mellon University in all publications reporting on direct or indirect use of this code or its derivatives.

ALL CODE, SOFTWARE, PROTOCOLS, AND ARCHITECTURES DEVELOPED BY THE CMU
MONARCH PROJECT ARE EXPERIMENTAL AND ARE KNOWN TO HAVE BUGS, SOME OF
WHICH MAY HAVE SERIOUS CONSEQUENCES. CARNEGIE MELLON PROVIDES THIS
SOFTWARE OR OTHER INTELLECTUAL PROPERTY IN ITS ``AS IS'' CONDITION,
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE OR
INTELLECTUAL PROPERTY, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

Carnegie Mellon encourages (but does not require) users of this
software or intellectual property to return any improvements or
extensions that they make, and to grant Carnegie Mellon the rights to redistribute these changes without encumbrance.

The WLSTATIC code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

*/

//#include <ip.h>

#include <wlstatic/wlstatic.h>
#include <wlstatic/wlstatic_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <energy-model.h>

#define max(a,b)        a > b ? a : b
#define CURRENT_TIME    Scheduler::instance().clock()

//#define DEBUG
//#define ERROR
//sroy+ash
#define MAXSEQ 1000000
#define usetimer_ 1
#ifdef DEBUG
static int extra_route_reply = 0;
static int limit_route_request = 0;
static int route_request = 0;
#endif


/*
  TCL Hooks
*/


int hdr_wlstatic::offset_;
static class WLSTATICHeaderClass : public PacketHeaderClass {
public:
        WLSTATICHeaderClass() : PacketHeaderClass("PacketHeader/WLSTATIC",
                                              sizeof(hdr_all_wlstatic)) {
	  bind_offset(&hdr_wlstatic::offset_);
	} 
} class_rtProtoWLSTATIC_hdr;

static class WLSTATICclass : public TclClass {
public:
        WLSTATICclass() : TclClass("Agent/WLSTATIC") {}
        TclObject* create(int argc, const char*const* argv) {
          assert(argc == 5);
          //return (new WLSTATIC((nsaddr_t) atoi(argv[4])));
	  return (new WLSTATIC((nsaddr_t) Address::instance().str2addr(argv[4])));
        }
} class_rtProtoWLSTATIC;
void 
WLSTATIC::sendBCast(Packet *p, bool jitter){
  for(int i = 0; i < numifs;i++){
	Packet *pkt = p->copy();
    if(jitter){
      Scheduler::instance().schedule(targetlist[i],pkt,0.01*Random::uniform());
    } else {
      Scheduler::instance().schedule(targetlist[i],pkt,0);
    }
  }
	Packet::free(p);
}

void
WLSTATIC::sendPacket(Packet *p,wlstatic_rt_entry * rt, double time){
  hdr_ip * ih = HDR_IP(p);
  if(ih->daddr() == IP_BROADCAST)
    sendBCast(p);
  else{
 	Scheduler::instance().schedule(rt->link,p,time);
  }	
}

int
WLSTATIC::command(int argc, const char*const* argv) {
  if(argc == 2) {
  Tcl& tcl = Tcl::instance();
    
    if(strncasecmp(argv[1], "id", 2) == 0) {
      tcl.resultf("%d", index);
      return TCL_OK;
    }
    
    if(strncasecmp(argv[1], "start", 2) == 0) {
      btimer.handle((Event*) 0);

#ifndef WLSTATIC_LINK_LAYER_DETECTION
      htimer.handle((Event*) 0);
      ntimer.handle((Event*) 0);
#endif // LINK LAYER DETECTION

      rtimer.handle((Event*) 0);
      return TCL_OK;
     }               
  }
  else if(argc == 3) {
    if(strcmp(argv[1], "index") == 0) {
      index = atoi(argv[2]);
      return TCL_OK;
    }

    else if(strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
      logtarget = (Trace*) TclObject::lookup(argv[2]);
      if(logtarget == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if(strcmp(argv[1], "drop-target") == 0) {
    int stat = rqueue.command(argc,argv);
      if (stat != TCL_OK) return stat;
      return Agent::command(argc, argv);
    }
    else if(strcmp(argv[1], "if-queue") == 0) {
    ifqueue = (PriQueue*) TclObject::lookup(argv[2]);
      
      if(ifqueue == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
  }
  //this is again change from here to...
  else if(argc == 4){
    if(strcmp(argv[1],"if-queue")==0) {
      //Format: $agent if-queue queuenum queueobj
      PriQueue * ifq = (PriQueue *) TclObject::lookup(argv[3]);
      int num = atoi(argv[2]);
      if(num == numifs) 
	numifs++;
      ifqueuelist[num] = ifq;
      if (ifq) 
	return TCL_OK;
      return TCL_ERROR;
    }
    if(strcmp(argv[1],"target")==0) {
      int num = atoi(argv[2]);
      if(num == numifs)
	numifs++;
      targetlist[num] = (NsObject *) TclObject::lookup(argv[3]);
      if(targetlist[num])
	return TCL_OK;
      return TCL_ERROR;
    }
  }
  else if(argc == 6)
  {
	if(strcmp(argv[1],"addstaticroute")==0)
	{
		int num_hops = atoi(argv[2]);
		int next_hop = atoi(argv[3]);
		int dest = atoi(argv[4]);
		int interface_index = atoi(argv[5]);
		if(interface_index>numifs || interface_index<0 || num_hops<0 || next_hop<0 || dest<0)
		{
			exit(187);
		}	
		wlstatic_rt_entry * rt;
		rt = rtable.rt_lookup(dest);
		if(!rt)
		{
			rt = rtable.rt_add(dest);
		}
		rt_update(rt,MAXSEQ,num_hops,next_hop,500);
		rt->link = targetlist[interface_index];
		rt->rt_flags = RTF_UP;
		return TCL_OK;
	}
	else
	{
		//printf("in the command function without call...in the else part\n");
		return TCL_ERROR;
	}	
	
   } 	
		
  return Agent::command(argc, argv);
}

/* 
   Constructor
*/

WLSTATIC::WLSTATIC(nsaddr_t id) : Agent(PT_WLSTATIC),
			  btimer(this), htimer(this), ntimer(this), 
			  rtimer(this), lrtimer(this), rqueue() {
 
                
  index = id;
  seqno = 2;
  bid = 1;

  LIST_INIT(&nbhead);
  LIST_INIT(&bihead);

  logtarget = 0;
  ifqueue = 0;
   numifs = 0;//this is also added see ~/forthesakeofMI
}

/*
  Timer_WL_WLs
*/

void
BroadcastTimer_WL::handle(Event*) {
  if(usetimer_ == 1)
  {	  
  	agent->id_purge();
	Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);
  }	
}

void
HelloTimer_WL::handle(Event*) {
   if(usetimer_ == 1)
   {
   	agent->sendHello();
   	double interval = MinHelloInterval + ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
   	assert(interval >= 0);
   	Scheduler::instance().schedule(this, &intr, interval);
   }	
}

void
NeighborTimer_WL::handle(Event*) {
  if(usetimer_ == 1)
  {
  	agent->nb_purge();
  	Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);
  }	
}

void
RouteCacheTimer_WL::handle(Event*) {
  if(usetimer_ == 1)
  {
  	agent->rt_purge();
	#define FREQUENCY 0.5 // sec
 	Scheduler::instance().schedule(this, &intr, FREQUENCY);
  }	
}

void
LocalRepairTimer_WL::handle(Event* p)  {  // SRD: 5/4/99
  if(usetimer_ == 1)
  {	
	wlstatic_rt_entry *rt;
	struct hdr_ip *ih = HDR_IP( (Packet *)p);

   	/* you get here after the timeout in a local repair attempt */
   	/*	fprintf(stderr, "%s\n", __FUNCTION__); */


    	rt = agent->rtable.rt_lookup(ih->daddr());
	
    	if (rt && rt->rt_flags != RTF_UP) {
    	// route is yet to be repaired
    	// I will be conservative and bring down the route
    	// and send route errors upstream.
    	/* The following assert fails, not sure why */
    	/* assert (rt->rt_flags == RTF_IN_REPAIR); */
		
      	//rt->rt_seqno++;
      	agent->rt_down(rt);
      	// send RERR
	#ifdef DEBUG
      	fprintf(stderr,"Node %d: Dst - %d, failed local repair\n",index, rt->rt_dst);
	#endif      
    	}
   	 Packet::free((Packet *)p);
  }	 
}


/*
   Broadcast ID_WL Management  Functions
*/


void
WLSTATIC::id_insert(nsaddr_t id, u_int32_t bid) {
BroadcastID_WL *b = new BroadcastID_WL(id, bid);

 assert(b);
 b->expire = CURRENT_TIME + BCAST_ID_SAVE;
 LIST_INSERT_HEAD(&bihead, b, link);
}

/* SRD */
bool
WLSTATIC::id_lookup(nsaddr_t id, u_int32_t bid) {
BroadcastID_WL *b = bihead.lh_first;
 
 // Search the list for a match of source and bid
 for( ; b; b = b->link.le_next) {
   if ((b->src == id) && (b->id == bid))
     return true;     
 }
 return false;
}

void
WLSTATIC::id_purge() {
BroadcastID_WL *b = bihead.lh_first;
BroadcastID_WL *bn;
double now = CURRENT_TIME;

 for(; b; b = bn) {
   bn = b->link.le_next;
   if(b->expire <= now) {
     LIST_REMOVE(b,link);
     delete b;
   }
 }
}

/*
  Helper Functions
*/

double
WLSTATIC::PerHopTime(wlstatic_rt_entry *rt) {
int num_non_zero = 0, i;
double total_latency = 0.0;

 if (!rt)
   return ((double) NODE_TRAVERSAL_TIME );
	
 for (i=0; i < MAX_HISTORY; i++) {
   if (rt->rt_disc_latency[i] > 0.0) {
      num_non_zero++;
      total_latency += rt->rt_disc_latency[i];
   }
 }
 if (num_non_zero > 0)
   return(total_latency / (double) num_non_zero);
 else
   return((double) NODE_TRAVERSAL_TIME);

}

/*
  Link Failure Management Functions
*/

static void
wlstatic_rt_failed_callback(Packet *p, void *arg) {
//sroy+ash
//printf("came here in line no 385...dont know from where????\n");
//  ((WLSTATIC*) arg)->rt_ll_failed(p);
}

/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void
WLSTATIC::rt_ll_failed(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
wlstatic_rt_entry *rt;
nsaddr_t broken_nbr = ch->next_hop_;

#ifndef WLSTATIC_LINK_LAYER_DETECTION
//sroy+ash
//printf("here in line 399 for checking CBK pkt drop\n");
//sroy+ash
 drop(p, DROP_RTR_MAC_CALLBACK);
#else 

 /*
  * Non-data packets and Broadcast Packets can be dropped.
  */
  if(! DATA_PACKET(ch->ptype()) ||
     (u_int32_t) ih->daddr() == IP_BROADCAST) {
   //sroy+ash
//	printf("here in line 410 for checking CBK pkt drop\n");
//sroy+ash
	  drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_broke(p);
	if((rt = rtable.rt_lookup(ih->daddr())) == 0) {
//sroy+ash
//printf("here in line 418 for checking CBK pkt drop\n");
//sroy+ash		
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_del(ch->next_hop_);

#ifdef WLSTATIC_LOCAL_REPAIR
  /* if the broken link is closer to the dest than source, 
     attempt a local repair. Otherwise, bring down the route. */


  if (ch->num_forwards() > rt->rt_hops) {
    local_rt_repair(rt, p); // local repair
    // retrieve all the packets in the ifq using this link,
    // queue the packets for which local repair is done, 
    return;
  }
  else	
#endif // LOCAL REPAIR	

  { //sroy+ash
//printf("here in line 440 for checking CBK pkt drop\n");
//sroy+ash
    drop(p, DROP_RTR_MAC_CALLBACK);
    // Do the same thing for other packets in the interface queue using the
    // broken link -Mahesh
    //
    //sroy+ash
    //this has been added again from here to....(see ~/forthesakeofMI
    if(rt == 0){
      for(int i = 0;i < numifs;i++){
	ifqueue = ifqueuelist[i];
	while((p = ifqueue->filter(broken_nbr))) {
	//sroy+ash
	//printf("here in line 453 for checking CBK pkt drop\n");
	//sroy+ash	
	  drop(p, DROP_RTR_MAC_CALLBACK);
	}	
      }
      nb_delete(broken_nbr);
    } else {
      for (int i = 0;i < numifs;i++)
	if(targetlist[i] == rt->link){
	  ifqueue = ifqueuelist[i];
	}///till here///sroy+ash
	while((p = ifqueue->filter(broken_nbr))) {
	//sroy+ash
	//printf("here in line 466 for checking CBK pkt drop\n");
	//sroy+ash
    	 drop(p, DROP_RTR_MAC_CALLBACK);
    	}	
    	nb_delete(broken_nbr);
      }
  }
#endif // LINK LAYER DETECTION
}

void
WLSTATIC::handle_link_failure(nsaddr_t id) {
wlstatic_rt_entry *rt, *rtn;
Packet *rerr = Packet::alloc();
struct hdr_wlstatic_error *re = HDR_WLSTATIC_ERROR(rerr);

 re->DestCount = 0;
 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next; 
   if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id) ) {
     assert (rt->rt_flags == RTF_UP);
     assert((rt->rt_seqno%2) == 0);
     rt->rt_seqno++;
     re->unreachable_dst[re->DestCount] = rt->rt_dst;
     re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
		     index, re->unreachable_dst[re->DestCount],
		     re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
     re->DestCount += 1;
     rt_down(rt);
   }
   // remove the lost neighbor from all the precursor lists
   rt->pc_delete(id);
 }   

 if (re->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr, false);
 }
 else {
   Packet::free(rerr);
 }
}

void
WLSTATIC::local_rt_repair(wlstatic_rt_entry *rt, Packet *p) {
#ifdef DEBUG
  fprintf(stderr,"%s: Dst - %d\n", __FUNCTION__, rt->rt_dst); 
#endif  
  // Buffer the packet 
  rqueue.enque(p);

  // mark the route as under repair 
  rt->rt_flags = RTF_IN_REPAIR;

  sendRequest(rt->rt_dst);

  // set up a timer interrupt
  Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);
}

void
WLSTATIC::rt_update(wlstatic_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
	       	nsaddr_t nexthop, double expire_time) {

     rt->rt_seqno = seqnum;
     rt->rt_hops = metric;
     rt->rt_flags = RTF_UP;
     rt->rt_nexthop = nexthop;
     rt->rt_expire = expire_time;
}

void
WLSTATIC::rt_down(wlstatic_rt_entry *rt) {
  /*
   *  Make sure that you don't "down" a route more than once.
   */

  if(rt->rt_flags == RTF_DOWN) {
    return;
  }

  // assert (rt->rt_seqno%2); // is the seqno odd?
  rt->rt_last_hop_count = rt->rt_hops;
  rt->rt_hops = INFINITY2;
  rt->rt_flags = RTF_DOWN;
  rt->rt_nexthop = 0;
  rt->rt_expire = 0;

} /* rt_down function */

/*
  Route Handling Functions
*/

void
WLSTATIC::rt_resolve(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
wlstatic_rt_entry *rt;

 /*
  *  Set the transmit failure callback.  That
  *  won't change.
  */
//
//sroy+ash
//printf("did it call wlstatic_rt_failed_callback()\n");
 ch->xmit_failure_ = wlstatic_rt_failed_callback;
 //sroy+ash
// printf("after calling wlstatic_rt_failed_callback()\n");
 ch->xmit_failure_data_ = (void*) this;
	rt = rtable.rt_lookup(ih->daddr());
 if(rt == 0) {
//	 printf("sroy+ash says there is something wrong in the static routing therefore dropping the packet\n");
	 drop(p, DROP_RTR_NO_ROUTE);
	 return;

/*	  rt = rtable.rt_add(ih->daddr());
	  //sroy+ash
	  if(usetimer_ == 0)
	  {		  
	  	create_static_routing_table(rt,ih->daddr());
	 	rt = rtable.rt_lookup(ih->daddr());
	  	assert(rt!=0);
	  }	
	  //sroy+ash */
 }
 else{
///sroy+ash this else part added by us
/*	 if(usetimer_ == 0)
	 {	 
		create_static_routing_table(rt,ih->daddr());
	  	rt = rtable.rt_lookup(ih->daddr());
	 	assert(rt!=0);
	 }	*/
 }	  

 /*
  * If the route is up, forward the packet 
  */
	
 if(rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   //sroy+ash
//   printf("sroy+ash wants alwyas to come here\n");
   //sroy+ash
   forward(rt, p, NO_DELAY);
 }
 /*
  *  if I am the source of the packet, then do a Route Request.
  */
	else if(ih->saddr() == index) {
   rqueue.enque(p);
   //sroy+ash
  // printf("sroy+ash DOES NOT want to come here\n");
   //sroy+ash
   sendRequest(rt->rt_dst);
 }
 /*
  *	A local repair is in progress. Buffer the packet. 
  */
 else if (rt->rt_flags == RTF_IN_REPAIR) {
   //sroy+ash
 //  printf("sroy+ash DOES NOT want to come here\n");
   //sroy+ash	 
   rqueue.enque(p);
 }

 /*
  * I am trying to forward a packet for someone else to which
  * I don't have a route.
  */
 else {
 Packet *rerr = Packet::alloc();
 struct hdr_wlstatic_error *re = HDR_WLSTATIC_ERROR(rerr);
 /* 
  * For now, drop the packet and send error upstream.
  * Now the route errors are broadcast to upstream
  * neighbors - Mahesh 09/11/99
  */	
 
   //sroy+ash
 //  printf("sroy+ash DOES NOT want to come here\n");
   //sroy+ash
   assert (rt->rt_flags == RTF_DOWN);
   re->DestCount = 0;
   re->unreachable_dst[re->DestCount] = rt->rt_dst;
   re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
   re->DestCount += 1;
#ifdef DEBUG
   fprintf(stderr, "%s: sending RERR...\n", __FUNCTION__);
#endif
   sendError(rerr, false);

   drop(p, DROP_RTR_NO_ROUTE);
 }

}

void
WLSTATIC::rt_purge() {
wlstatic_rt_entry *rt, *rtn;
double now = CURRENT_TIME;
double delay = 0.0;
Packet *p;

 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next;
   if ((rt->rt_flags == RTF_UP) && (rt->rt_expire < now)) {
   // if a valid route has expired, purge all packets from 
   // send buffer and invalidate the route.                    
	assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
       fprintf(stderr, "%s: calling drop()\n",
                       __FUNCTION__);
#endif // DEBUG
       drop(p, DROP_RTR_NO_ROUTE);
     }
     rt->rt_seqno++;
     assert (rt->rt_seqno%2);
     rt_down(rt);
   }
   else if (rt->rt_flags == RTF_UP) {
   // If the route is not expired,
   // and there are packets in the sendbuffer waiting,
   // forward them. This should not be needed, but this extra 
   // check does no harm.
     assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
       forward (rt, p, delay);
       delay += ARP_DELAY;
     }
   } 
   else if (rqueue.find(rt->rt_dst))
   // If the route is down and 
   // if there is a packet for this destination waiting in
   // the sendbuffer, then send out route request. sendRequest
   // will check whether it is time to really send out request
   // or not.
   // This may not be crucial to do it here, as each generated 
   // packet will do a sendRequest anyway.

     sendRequest(rt->rt_dst); 
   }

}

/*
  Packet Reception Routines
*/

void
WLSTATIC::recv(Packet *p, Handler*) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 assert(initialized());
 //assert(p->incoming == 0);
 // XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.

 if(ch->ptype() == PT_WLSTATIC) {
   ih->ttl_ -= 1;
   recvWLSTATIC(p);
   return;
 }

 /*
  *  Must be a packet I'm originating...
  */
if((ih->saddr() == index) && (ch->num_forwards() == 0)) {
 /*
  * Add the IP Header
  */
   ch->size() += IP_HDR_LEN;
   // Added by Parag Dadhania && John Novatnack to handle broadcasting
   if ( (u_int32_t)ih->daddr() != IP_BROADCAST)//sroy+ash...we are not changing this as this seems okay although does not match with what BTP says
     ih->ttl_ = NETWORK_DIAMETER;
}
 /*
  *  I received a packet that I sent.  Probably
  *  a routing loop.
  */
else if(ih->saddr() == index) {
   drop(p, DROP_RTR_ROUTE_LOOP);
   return;
 }
 /*
  *  Packet I'm forwarding...
  */
 else {
 /*
  *  Check the TTL.  If it is zero, then discard.
  */
   if(--ih->ttl_ == 0) {
     drop(p, DROP_RTR_TTL);
     return;
   }
 }
// Added by Parag Dadhania && John Novatnack to handle broadcasting
 if ( (u_int32_t)ih->daddr() != IP_BROADCAST)//sroy+ash...we are not changing this as this seems okay although does not match with what BTP says
{
   //sroy+ash
   //printf("going to call rt_resolve\n");
   //sroy+ash
   rt_resolve(p);
}   
 else//sroy+ash...we are not changing this as this seems okay although does not match with what BTP says..this else part also
 {//sroy+ash
   //printf("DID_WL NOTcall rt_resolve\n");
   //sroy+ash	 
   forward((wlstatic_rt_entry*) 0, p, NO_DELAY);
 }  
}


void
WLSTATIC::recvWLSTATIC(Packet *p) {
struct hdr_wlstatic *ah = HDR_WLSTATIC(p);
struct hdr_ip *ih = HDR_IP(p);

 assert(ih->sport() == RT_PORT);
 assert(ih->dport() == RT_PORT);

 /*
  * Incoming Packets.
  */
 switch(ah->ah_type) {

 case WLSTATICTYPE_RREQ:
   recvRequest(p);
   break;

 case WLSTATICTYPE_RREP:
   recvReply(p);
   break;

 case WLSTATICTYPE_RERR:
   recvError(p);
   break;

 case WLSTATICTYPE_HELLO:
   recvHello(p);
   break;
        
 default:
   fprintf(stderr, "Invalid WLSTATIC type (%x)\n", ah->ah_type);
   exit(1);
 }

}


void
WLSTATIC::recvRequest(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_request *rq = HDR_WLSTATIC_REQUEST(p);
 struct hdr_cmn * ch = HDR_CMN(p);///sroy+ash....compare with ~/forthesakeofMI
wlstatic_rt_entry *rt;

  /*
   * Drop if:
   *      - I'm the source
   *      - I recently heard this request.
   */

  if(rq->rq_src == index) {
#ifdef DEBUG
    fprintf(stderr, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
    Packet::free(p);
    return;
  } 

 if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
   fprintf(stderr, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG
 
   Packet::free(p);
   return;
 }

 /*
  * Cache the broadcast ID_WL
  */
 id_insert(rq->rq_src, rq->rq_bcast_id);



 /* 
  * We are either going to forward the REQUEST or generate a
  * REPLY. Before we do anything, we make sure that the REVERSE
  * route is in the route table.
  */
 wlstatic_rt_entry *rt0; // rt0 is the reverse route 
   
   rt0 = rtable.rt_lookup(rq->rq_src);
   if(rt0 == 0) { /* if not in the route table */
   // create an entry for the reverse route.
     rt0 = rtable.rt_add(rq->rq_src);
     rt0->link = targetlist[ch->iface() - ((Mac *)ifqueuelist[0]->target())->addr()];///this is also changed/.sroy+ash see ~/forthesakeofMI
   }
  
   rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));

   if ( (rq->rq_src_seqno > rt0->rt_seqno ) ||
    	((rq->rq_src_seqno == rt0->rt_seqno) && 
	 (rq->rq_hop_count < rt0->rt_hops)) ) {
   // If we have a fresher seq no. or lesser #hops for the 
   // same seq no., update the rt entry. Else don't bother.
rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
     	       max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)) );
     if (rt0->rt_req_timeout > 0.0) {
     // Reset the soft state and 
     // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
     // This is because route is used in the forward direction,
     // but only sources get benefited by this change
       rt0->rt_req_cnt = 0;
       rt0->rt_req_timeout = 0.0; 
       rt0->rt_req_last_ttl = rq->rq_hop_count;
       rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
     }

     /* Find out whether any buffered packet can benefit from the 
      * reverse route.
      * May need some change in the following code - Mahesh 09/11/99
      */
     assert (rt0->rt_flags == RTF_UP);
     Packet *buffered_pkt;
     while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
       if (rt0 && (rt0->rt_flags == RTF_UP)) {
	assert(rt0->rt_hops != INFINITY2);
         forward(rt0, buffered_pkt, NO_DELAY);
       }
     }
   } 
   // End for putting reverse route in rt table


 /*
  * We have taken care of the reverse route stuff.
  * Now see whether we can send a route reply. 
  */

 rt = rtable.rt_lookup(rq->rq_dst);

 // First check if I am the destination ..

 if(rq->rq_dst == index) {

#ifdef DEBUG
   fprintf(stderr, "%d - %s: destination sending reply\n",
                   index, __FUNCTION__);
#endif // DEBUG

               
   // Just to be safe, I use the max. Somebody may have
   // incremented the dst seqno.
   seqno = max(seqno, rq->rq_dst_seqno)+1;
   if (seqno%2) seqno++;

   sendReply(rq->rq_src,           // IP Destination
             1,                    // Hop Count
             index,                // Dest IP Address
             seqno,                // Dest Sequence Num
             MY_ROUTE_TIMEOUT,     // Lifetime
             rq->rq_timestamp);    // timestamp
 
   Packet::free(p);
 }

 // I am not the destination, but I may have a fresh enough route.

 else if (rt && (rt->rt_hops != INFINITY2) && 
	  	(rt->rt_seqno >= rq->rq_dst_seqno) ) {

   //assert (rt->rt_flags == RTF_UP);
   assert(rq->rq_dst == rt->rt_dst);
   //assert ((rt->rt_seqno%2) == 0);	// is the seqno even?
   sendReply(rq->rq_src,
             rt->rt_hops + 1,
             rq->rq_dst,
             rt->rt_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp);
   // Insert nexthops to RREQ source and RREQ destination in the
   // precursor lists of destination and source respectively
   rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
   rt0->pc_insert(rt->rt_nexthop); // nexthop to RREQ destination
//////////////////although this part not there...but seems to be an enhancement...sroy+ash
#ifdef RREQ_GRAT_RREP  

   sendReply(rq->rq_dst,
             rq->rq_hop_count,
             rq->rq_src,
             rq->rq_src_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp);
#endif
/////till this part  
   
// TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT
   
// DONE: Included gratuitous replies to be sent as per IETF wlstatic draft specification. As of now, G flag has not been dynamically used and is always set or reset in wlstatic-packet.h --- Anant Utgikar, 09/16/02.

	Packet::free(p);
 }
 /*
  * Can't reply. So forward the  Route Request
  */
 else {
   ih->saddr() = index;
   ih->daddr() = IP_BROADCAST;
   rq->rq_hop_count += 1;
   // Maximum sequence number seen en route
   if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
   forward((wlstatic_rt_entry*) 0, p, DELAY);
 }

}


void
WLSTATIC::recvReply(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);//this was commnted in BTP...see sroy+ash!!
struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_reply *rp = HDR_WLSTATIC_REPLY(p);
wlstatic_rt_entry *rt;
char suppress_reply = 0;
double delay = 0.0;
	
#ifdef DEBUG
 fprintf(stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__);
#endif // DEBUG


 /*
  *  Got a reply. So reset the "soft state" maintained for 
  *  route requests in the request table. We don't really have
  *  have a separate request table. It is just a part of the
  *  routing table itself. 
  */
 // Note that rp_dst is the dest of the data packets, not the
 // the dest of the reply, which is the src of the data packets.

 rt = rtable.rt_lookup(rp->rp_dst);
        
 /*
  *  If I don't have a rt entry to this host... adding
  */
 if(rt == 0) {
   rt = rtable.rt_add(rp->rp_dst);
 }

 /*
  * Add a forward route table entry... here I am following 
  * Perkins-Royer WLSTATIC paper almost literally - SRD 5/99
  */

 if ( (rt->rt_seqno < rp->rp_dst_seqno) ||   // newer route 
      ((rt->rt_seqno == rp->rp_dst_seqno) &&  
       (rt->rt_hops > rp->rp_hop_count)) ) { // shorter or better route
	
  // Update the rt entry 
  rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count,
		rp->rp_src, CURRENT_TIME + rp->rp_lifetime);

  // reset the soft state
  rt->rt_req_cnt = 0;
  rt->rt_req_timeout = 0.0; 
  rt->rt_req_last_ttl = rp->rp_hop_count;
  rt->link = targetlist[ch->iface() - ((Mac *)ifqueuelist[0]->target())->addr()];///this line is also...sroy+ash...se ~forthesakeofMI
  
if (ih->daddr() == index) { // If I am the original source
  // Update the route discovery latency statistics
  // rp->rp_timestamp is the time of request origination
		
    rt->rt_disc_latency[rt->hist_indx] = (CURRENT_TIME - rp->rp_timestamp)
                                         / (double) rp->rp_hop_count;
    // increment indx for next time
    rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
  }	

  /*
   * Send all packets queued in the sendbuffer destined for
   * this destination. 
   * XXX - observe the "second" use of p.
   */
  Packet *buf_pkt;
  while((buf_pkt = rqueue.deque(rt->rt_dst))) {
    if(rt->rt_hops != INFINITY2) {
          assert (rt->rt_flags == RTF_UP);
    // Delay them a little to help ARP. Otherwise ARP 
    // may drop packets. -SRD 5/23/99
      forward(rt, buf_pkt, delay);
      delay += ARP_DELAY;
    }
  }
 }
 else {
  suppress_reply = 1;
 }

 /*
  * If reply is for me, discard it.
  */

if(ih->daddr() == index || suppress_reply) {
   Packet::free(p);
 }
 /*
  * Otherwise, forward the Route Reply.
  */
 else {
 // Find the rt entry
wlstatic_rt_entry *rt0 = rtable.rt_lookup(ih->daddr());
   // If the rt is up, forward
   if(rt0 && (rt0->rt_hops != INFINITY2)) {
        assert (rt0->rt_flags == RTF_UP);
     rp->rp_hop_count += 1;
     rp->rp_src = index;
     forward(rt0, p, NO_DELAY);
     // Insert the nexthop towards the RREQ source to 
     // the precursor list of the RREQ destination
     rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
     
   }
   else {
   // I don't know how to forward .. drop the reply. 
#ifdef DEBUG
     fprintf(stderr, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
     drop(p, DROP_RTR_NO_ROUTE);
   }
 }
}


void
WLSTATIC::recvError(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_error *re = HDR_WLSTATIC_ERROR(p);
  struct hdr_cmn * ch = HDR_CMN(p);///this is added sroy+ash/.....~/forthesakeofMI
wlstatic_rt_entry *rt;
u_int8_t i;
Packet *rerr = Packet::alloc();
struct hdr_wlstatic_error *nre = HDR_WLSTATIC_ERROR(rerr);

 nre->DestCount = 0;

 for (i=0; i<re->DestCount; i++) {
 // For each unreachable destination
   rt = rtable.rt_lookup(re->unreachable_dst[i]);
   if ( rt && (rt->rt_hops != INFINITY2) &&
	(rt->rt_nexthop == ih->saddr()) &&
     	(rt->rt_seqno <= re->unreachable_dst_seqno[i]) ) {
	assert(rt->rt_flags == RTF_UP);
	assert((rt->rt_seqno%2) == 0); // is the seqno even?
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__,CURRENT_TIME,
		     index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
		     re->unreachable_dst[i],re->unreachable_dst_seqno[i],
	             ih->saddr());
#endif // DEBUG
     	rt->rt_seqno = re->unreachable_dst_seqno[i];
     	rt_down(rt);

   // Not sure whether this is the right thing to do
   Packet *pkt;
 /////////////sroy+ash
   //fromm here to.....	
   for(int i = 0;i < numifs;i++)
	  if(rt->link == targetlist[i]){
	    ifqueue = ifqueuelist[i];
	    break;
	  }////till here
	while((pkt = ifqueue->filter(ih->saddr()))) {
		//sroy+ash
	//printf("here in line 1140 for checking CBK pkt drop\n");
	//sroy+ash
        	drop(pkt, DROP_RTR_MAC_CALLBACK);
     	}
////again this is added sroy+ash   
	rt_down(rt);//till here....see ~/forthesakeofMI
	
     // if precursor list non-empty add to RERR and delete the precursor list
     	if (!rt->pc_empty()) {
     		nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
     		nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
     		nre->DestCount += 1;
		rt->pc_delete();
     	}
   }
 } 

 if (nre->DestCount > 0) {
#ifdef DEBUG	
   fprintf(stderr, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr);
 }
 else {
   Packet::free(rerr);
 }

 Packet::free(p);
}


/*
   Packet Transmission Routines
*/

void
WLSTATIC::forward(wlstatic_rt_entry *rt, Packet *p, double delay) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 if(ih->ttl_ == 0) {

#ifdef DEBUG
  fprintf(stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG
 
  drop(p, DROP_RTR_TTL);
  return;
 }

 if (rt) {
   assert(rt->rt_flags == RTF_UP);
   rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
   ch->next_hop_ = rt->rt_nexthop;
   ch->addr_type() = NS_AF_INET;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }
 else { // if it is a broadcast packet
   assert(ch->ptype() == PT_WLSTATIC);
   assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
   ch->addr_type() = NS_AF_NONE;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }

if (ih->daddr() == (nsaddr_t) IP_BROADCAST) {
 // If it is a broadcast packet
   assert(rt == 0);
   /*
    *  Jitter the sending of broadcast packets by 10ms
    */
 //  Scheduler::instance().schedule(target_, p,
      //				   0.01 * Random::uniform());///these two lines are commented by sroy+ash...see ~/frothesakeofMI...for reason
   sendBCast(p);//for the above line this line is added...sroy+ash
 }
 else { // Not a broadcast packet 
   if(delay > 0.0) {
   //  Scheduler::instance().schedule(target_, p, delay);///these two lines are commented by sroy+ash...see ~/frothesakeofMI...for reason
	   sendPacket(p,rt,delay);//for the above line this line is added...sroy+ash

   }
   else {
   // Not a broadcast packet, no delay, send immediately
    // Scheduler::instance().schedule(target_, p, 0.);///these two lines are commented by sroy+ash...see ~/frothesakeofMI...for reason

	    sendPacket(p,rt,0);//for the above line this line is added...sroy+ash

   }
 }

}


void
WLSTATIC::sendRequest(nsaddr_t dst) {
// Allocate a RREQ packet 
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_request *rq = HDR_WLSTATIC_REQUEST(p);
wlstatic_rt_entry *rt = rtable.rt_lookup(dst);

 assert(rt);

 /*
  *  Rate limit sending of Route Requests. We are very conservative
  *  about sending out route requests. 
  */

 if (rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   Packet::free((Packet *)p);
   return;
 }

 if (rt->rt_req_timeout > CURRENT_TIME) {
   Packet::free((Packet *)p);
   return;
 }

 // rt_req_cnt is the no. of times we did network-wide broadcast
 // RREQ_RETRIES is the maximum number we will allow before 
 // going to a long timeout.

 if (rt->rt_req_cnt > RREQ_RETRIES) {
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
   rt->rt_req_cnt = 0;
 Packet *buf_pkt;
   while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
       drop(buf_pkt, DROP_RTR_NO_ROUTE);
   }
   Packet::free((Packet *)p);
   return;
 }

#ifdef DEBUG
   fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d\n",
                    ++route_request, index, rt->rt_dst);
#endif // DEBUG

 // Determine the TTL to be used this time. 
 // Dynamic TTL evaluation - SRD

 rt->rt_req_last_ttl = max(rt->rt_req_last_ttl,rt->rt_last_hop_count);

 if (0 == rt->rt_req_last_ttl) {
 // first time query broadcast
   ih->ttl_ = TTL_START;
 }
 else {
 // Expanding ring search.
   if (rt->rt_req_last_ttl < TTL_THRESHOLD)
     ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
   else {
   // network-wide broadcast
     ih->ttl_ = NETWORK_DIAMETER;
     rt->rt_req_cnt += 1;
   }
 }

 // remember the TTL used  for the next time
 rt->rt_req_last_ttl = ih->ttl_;

 // PerHopTime is the roundtrip time per hop for route requests.
 // The factor 2.0 is just to be safe .. SRD 5/22/99
 // Also note that we are making timeouts to be larger if we have 
 // done network wide broadcast before. 

 rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt); 
 if (rt->rt_req_cnt > 0)
   rt->rt_req_timeout *= rt->rt_req_cnt;
 rt->rt_req_timeout += CURRENT_TIME;

 // Don't let the timeout to be too large, however .. SRD 6/8/99
 if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
 rt->rt_expire = 0;

#ifdef DEBUG
 fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
	         ++route_request, 
		 index, rt->rt_dst, 
		 rt->rt_req_timeout - CURRENT_TIME);
#endif	// DEBUG
	

 // Fill out the RREQ packet 
 // ch->uid() = 0;
 ch->ptype() = PT_WLSTATIC;
 ch->size() = IP_HDR_LEN + rq->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // WLSTATIC hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;

 // Fill up some more fields. 
 rq->rq_type = WLSTATICTYPE_RREQ;
 rq->rq_hop_count = 1;
 rq->rq_bcast_id = bid++;
 rq->rq_dst = dst;
 rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
 rq->rq_src = index;
 seqno += 2;
 assert ((seqno%2) == 0);
 rq->rq_src_seqno = seqno;
 rq->rq_timestamp = CURRENT_TIME;

// Scheduler::instance().schedule(target_, p, 0.);//This is commented...~/forthesakeofMI
sendBCast(p,false);///this is added.....sroy+ash
}

void
WLSTATIC::sendReply(nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
                u_int32_t rpseq, u_int32_t lifetime, double timestamp) {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_reply *rp = HDR_WLSTATIC_REPLY(p);
wlstatic_rt_entry *rt = rtable.rt_lookup(ipdst);

#ifdef DEBUG
fprintf(stderr, "sending Reply from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
 assert(rt);

 rp->rp_type = WLSTATICTYPE_RREP;
 //rp->rp_flags = 0x00;
 rp->rp_hop_count = hop_count;
 rp->rp_dst = rpdst;
 rp->rp_dst_seqno = rpseq;
 rp->rp_src = index;
 rp->rp_lifetime = lifetime;
 rp->rp_timestamp = timestamp;
   
 // ch->uid() = 0;
 ch->ptype() = PT_WLSTATIC;
 ch->size() = IP_HDR_LEN + rp->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_INET;
 ch->next_hop_ = rt->rt_nexthop;
 ch->prev_hop_ = index;          // WLSTATIC hack
 ch->direction() = hdr_cmn::DOWN;

 ih->saddr() = index;
 ih->daddr() = ipdst;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = NETWORK_DIAMETER;

// Scheduler::instance().schedule(target_, p, 0.);//This is commented...~/forthesakeofMI
 sendPacket(p,rt);///this is added.....sroy+ash
}

void
WLSTATIC::sendError(Packet *p, bool jitter) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_error *re = HDR_WLSTATIC_ERROR(p);
    
#ifdef ERROR
fprintf(stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 re->re_type = WLSTATICTYPE_RERR;
 //re->reserved[0] = 0x00; re->reserved[1] = 0x00;
 // DestCount and list of unreachable destinations are already filled

 // ch->uid() = 0;
 ch->ptype() = PT_WLSTATIC;
 ch->size() = IP_HDR_LEN + re->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->next_hop_ = 0;
 ch->prev_hop_ = index;          // WLSTATIC hack
 ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

 // Do we need any jitter? Yes
 if (jitter)
// 	Scheduler::instance().schedule(target_, p, 0.01*Random::uniform());//commented by sroy+ash...~/forthesakeofMI
 	 sendBCast(p);//this was added in that place
 else
// 	Scheduler::instance().schedule(target_, p, 0.0);//commented by sroy+ash...~/forthesakeofMI
 	 sendBCast(p,false);//this was added in that place


}


/*
   Neighbor Management Functions
*/

void
WLSTATIC::sendHello() {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_reply *rh = HDR_WLSTATIC_REPLY(p);

#ifdef DEBUG
fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 rh->rp_type = WLSTATICTYPE_HELLO;
 //rh->rp_flags = 0x00;
 rh->rp_hop_count = 1;
 rh->rp_dst = index;
 rh->rp_dst_seqno = seqno;
 rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;

 // ch->uid() = 0;
 ch->ptype() = PT_WLSTATIC;
 ch->size() = IP_HDR_LEN + rh->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // WLSTATIC hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

// Scheduler::instance().schedule(target_, p, 0.0);//commented by sroy+ash...~/forthesakeofMI
sendBCast(p,false);///this is added in that place
}


void
WLSTATIC::recvHello(Packet *p) {
//struct hdr_ip *ih = HDR_IP(p);
struct hdr_wlstatic_reply *rp = HDR_WLSTATIC_REPLY(p);
WLSTATIC_Neighbor *nb;

 nb = nb_lookup(rp->rp_dst);
 if(nb == 0) {
   nb_insert(rp->rp_dst);
 }
 else {
   nb->nb_expire = CURRENT_TIME +
                   (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 }

 Packet::free(p);
}

void
WLSTATIC::nb_insert(nsaddr_t id) {
WLSTATIC_Neighbor *nb = new WLSTATIC_Neighbor(id);

 assert(nb);
 nb->nb_expire = CURRENT_TIME +
                (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 LIST_INSERT_HEAD(&nbhead, nb, nb_link);
 seqno += 2;             // set of neighbors changed
 assert ((seqno%2) == 0);
}


WLSTATIC_Neighbor*
WLSTATIC::nb_lookup(nsaddr_t id) {
WLSTATIC_Neighbor *nb = nbhead.lh_first;

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) break;
 }
 return nb;
}


/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */
void
WLSTATIC::nb_delete(nsaddr_t id) {
WLSTATIC_Neighbor *nb = nbhead.lh_first;

 log_link_del(id);
 seqno += 2;     // Set of neighbors changed
 assert ((seqno%2) == 0);

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) {
     LIST_REMOVE(nb,nb_link);
     delete nb;
     break;
   }
 }

 handle_link_failure(id);

}


/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
void
WLSTATIC::nb_purge() {
WLSTATIC_Neighbor *nb = nbhead.lh_first;
WLSTATIC_Neighbor *nbn;
double now = CURRENT_TIME;

 for(; nb; nb = nbn) {
   nbn = nb->nb_link.le_next;
   if(nb->nb_expire <= now) {
//     nb_delete(nb->nb_addr);this is commented as the same was done in BTP...sroy+ash
   }
 }

}


