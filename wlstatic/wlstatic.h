/*
Copyright (c) 2003,2004 Ashwini, Sabyasachi Roy . Indian Institute Technology, Kanpur, India.
All Rights Reserved. 
*/



#ifndef __wlstatic_h__
#define __wlstatic_h__


#include <cmu-trace.h>
#include <priqueue.h>
#include <wlstatic/wlstatic_rtable.h>
#include <wlstatic/wlstatic_rqueue.h>


#define WLSTATIC_LOCAL_REPAIR

/*
  Allows WLSTATIC to use link-layer (802.11) feedback in determining when
  links are up/down.
*/
#define WLSTATIC_LINK_LAYER_DETECTION

#define WLSTATIC_USE_LL_METRIC

class WLSTATIC;

#define MY_ROUTE_TIMEOUT        10                      	// 100 seconds
#define ACTIVE_ROUTE_TIMEOUT    10				// 50 seconds
#define REV_ROUTE_LIFE          6				// 5  seconds
#define BCAST_ID_SAVE           6				// 3 seconds


// No. of times to do network-wide search before timing out for 
// MAX_RREQ_TIMEOUT sec. 
#define RREQ_RETRIES            3  
// timeout after doing network-wide search RREQ_RETRIES times
#define MAX_RREQ_TIMEOUT	10.0 //sec

/* Various constants used for the expanding ring search */
#define TTL_START     5
#define TTL_THRESHOLD 7
#define TTL_INCREMENT 2 

// This should be somewhat related to arp timeout
#define NODE_TRAVERSAL_TIME     0.03             // 30 ms
#define LOCAL_REPAIR_WAIT_TIME  0.15 //sec

// Should be set by the user using best guess (conservative) 
#define NETWORK_DIAMETER        30             // 30 hops

// Must be larger than the time difference between a node propagates a route 
// request and gets the route reply back.

//#define RREP_WAIT_TIME     (3 * NODE_TRAVERSAL_TIME * NETWORK_DIAMETER) // ms
//#define RREP_WAIT_TIME     (2 * REV_ROUTE_LIFE)  // seconds
#define RREP_WAIT_TIME         1.0  // sec

#define ID_NOT_FOUND    0x00
#define ID_FOUND        0x01
//#define INFINITY        0xff

// The followings are used for the forward() function. Controls pacing.
#define DELAY 1.0           // random delay
#define NO_DELAY -1.0       // no delay 

// think it should be 30 ms
#define ARP_DELAY 0.01      // fixed delay to keep arp happy


#define HELLO_INTERVAL          1               // 1000 ms
#define ALLOWED_HELLO_LOSS      3               // packets
#define BAD_LINK_LIFETIME       3               // 3000 ms
#define MaxHelloInterval        (1.25 * HELLO_INTERVAL)
#define MinHelloInterval        (0.75 * HELLO_INTERVAL)

/*
  Timers (Broadcast ID, Hello, Neighbor Cache, Route Cache)
*/
class BroadcastTimer_WL : public Handler {
public:
        BroadcastTimer_WL(WLSTATIC* a) : agent(a) {}
        void	handle(Event*);
private:
        WLSTATIC    *agent;
	Event	intr;
};

class HelloTimer_WL : public Handler {
public:
        HelloTimer_WL(WLSTATIC* a) : agent(a) {}
        void	handle(Event*);
private:
        WLSTATIC    *agent;
	Event	intr;
};

class NeighborTimer_WL : public Handler {
public:
        NeighborTimer_WL(WLSTATIC* a) : agent(a) {}
        void	handle(Event*);
private:
        WLSTATIC    *agent;
	Event	intr;
};

class RouteCacheTimer_WL : public Handler {
public:
        RouteCacheTimer_WL(WLSTATIC* a) : agent(a) {}
        void	handle(Event*);
private:
        WLSTATIC    *agent;
	Event	intr;
};

class LocalRepairTimer_WL : public Handler {
public:
        LocalRepairTimer_WL(WLSTATIC* a) : agent(a) {}
        void	handle(Event*);
private:
        WLSTATIC    *agent;
	Event	intr;
};


/*
  Broadcast ID Cache
*/
class BroadcastID_WL {
        friend class WLSTATIC;
 public:
        BroadcastID_WL(nsaddr_t i, u_int32_t b) { src = i; id = b;  }
 protected:
        LIST_ENTRY(BroadcastID_WL) link;
        nsaddr_t        src;
        u_int32_t       id;
        double          expire;         // now + BCAST_ID_SAVE s
};

LIST_HEAD(wlstatic_bcache, BroadcastID_WL);

#define MAXIF 10 ///this is the max number of interfaces allowed...
/*
  The Routing Agent
*/
class WLSTATIC: public Agent {

  /*
   * make some friends first 
   */

        friend class wlstatic_rt_entry;
        friend class BroadcastTimer_WL;
        friend class HelloTimer_WL;
        friend class NeighborTimer_WL;
        friend class RouteCacheTimer_WL;
        friend class LocalRepairTimer_WL;

 public:
        WLSTATIC(nsaddr_t id);

        void		recv(Packet *p, Handler *);

 protected:
        int             command(int, const char *const *);
        int             initialized() { return 1 && target_; }

        /*
         * Route Table Management
         */
        void            rt_resolve(Packet *p);
        void            rt_update(wlstatic_rt_entry *rt, u_int32_t seqnum,
		     	  	u_int16_t metric, nsaddr_t nexthop,
		      		double expire_time);
        void            rt_down(wlstatic_rt_entry *rt);
        void            local_rt_repair(wlstatic_rt_entry *rt, Packet *p);
 public:
        void            rt_ll_failed(Packet *p);
        void            handle_link_failure(nsaddr_t id);
 protected:
        void            rt_purge(void);

        void            enque(wlstatic_rt_entry *rt, Packet *p);
        Packet*         deque(wlstatic_rt_entry *rt);

        /*
         * Neighbor Management
         */
        void            nb_insert(nsaddr_t id);
        WLSTATIC_Neighbor*       nb_lookup(nsaddr_t id);
        void            nb_delete(nsaddr_t id);
        void            nb_purge(void);

        /*
         * Broadcast ID Management
         */

        void            id_insert(nsaddr_t id, u_int32_t bid);
        bool	        id_lookup(nsaddr_t id, u_int32_t bid);
        void            id_purge(void);

        /*
         * Packet TX Routines
         */
        void            forward(wlstatic_rt_entry *rt, Packet *p, double delay);
        void            sendHello(void);
        void            sendRequest(nsaddr_t dst);

        void            sendReply(nsaddr_t ipdst, u_int32_t hop_count,
                                  nsaddr_t rpdst, u_int32_t rpseq,
                                  u_int32_t lifetime, double timestamp);
        void            sendError(Packet *p, bool jitter = true);
	
	void 		sendBCast(Packet *p, bool jitter=true);
	void		sendPacket(Packet *p, wlstatic_rt_entry *,double time=0.0); 
        /*
         * Packet RX Routines
         */
        void            recvWLSTATIC(Packet *p);
        void            recvHello(Packet *p);
        void            recvRequest(Packet *p);
        void            recvReply(Packet *p);
        void            recvError(Packet *p);

	/*
	 * History management
	 */
	
	double 		PerHopTime(wlstatic_rt_entry *rt);


        nsaddr_t        index;                  // IP Address of this node
        u_int32_t       seqno;                  // Sequence Number
        int             bid;                    // Broadcast ID

        wlstatic_rtable         rthead;                 // routing table
        wlstatic_ncache         nbhead;                 // Neighbor Cache
        wlstatic_bcache          bihead;                 // Broadcast ID Cache

        /*
         * Timers
         */
        BroadcastTimer_WL  btimer;
        HelloTimer_WL      htimer;
        NeighborTimer_WL   ntimer;
        RouteCacheTimer_WL rtimer;
        LocalRepairTimer_WL lrtimer;

        /*
         * Routing Table
         */
        wlstatic_rtable          rtable;
        /*
         *  A "drop-front" queue used by the routing layer to buffer
         *  packets to which it does not have a route.
         */
        wlstatic_rqueue         rqueue;

        /*
         * A mechanism for logging the contents of the routing
         * table.
         */
        Trace           *logtarget;

        /*
         * A pointer to the network interface queue that sits
         * between the "classifier" and the "link layer".
         */
	//this is again added ....see from ~/forthesakeofMI
	int numifs;	//number of interfaces
	NsObject * targetlist[MAXIF];
	PriQueue * ifqueuelist[MAXIF];
        PriQueue        *ifqueue;

        /*
         * Logging stuff
         */
        void            log_link_del(nsaddr_t dst);
        void            log_link_broke(Packet *p);
        void            log_link_kept(nsaddr_t dst);
};

#endif /* __wlstatic_h__ */
