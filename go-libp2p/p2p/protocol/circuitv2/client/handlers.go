package client

import (
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	pbv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/util"
)

var (
	StreamTimeout = 1 * time.Minute
	AcceptTimeout = 10 * time.Second
)

func (c *Client) handleStreamV2(s network.Stream) {
	log.Debugf("new relay/v2 stream from: %s", s.Conn().RemotePeer())

	s.SetReadDeadline(time.Now().Add(StreamTimeout))

	rd := util.NewDelimitedReader(s, maxMessageSize)

	writeResponse := func(status pbv2.Status) error {
		s.SetWriteDeadline(time.Now().Add(StreamTimeout))
		wr := util.NewDelimitedWriter(s)

		var msg pbv2.StopMessage
		msg.Type = pbv2.StopMessage_STATUS.Enum()
		msg.Status = status.Enum()

		err := wr.WriteMsg(&msg)
		s.SetWriteDeadline(time.Time{})
		return err
	}

	handleError := func(status pbv2.Status) {
		log.Debugf("protocol error: %s (%d)", pbv2.Status_name[int32(status)], status)
		err := writeResponse(status)
		if err != nil {
			s.Reset()
			log.Debugf("error writing circuit response: %s", err.Error())
		} else {
			s.Close()
		}
	}

	var msg pbv2.StopMessage

	err := rd.ReadMsg(&msg)
	if err != nil {
		handleError(pbv2.Status_MALFORMED_MESSAGE)
		rd.Close()
		return
	}
	// reset stream deadline as message has been read
	s.SetReadDeadline(time.Time{})

	if msg.GetType() != pbv2.StopMessage_CONNECT {
		handleError(pbv2.Status_UNEXPECTED_MESSAGE)
		rd.Close()
		return
	}

	src, err := util.PeerToPeerInfoV2(msg.GetPeer())
	if err != nil {
		handleError(pbv2.Status_MALFORMED_MESSAGE)
		rd.Close()
		return
	}

	// check for a limit provided by the relay; if the limit is not nil, then this is a limited
	// relay connection and we mark the connection as transient.
	var stat network.ConnStats
	if limit := msg.GetLimit(); limit != nil {
		stat.Limited = true
		stat.Extra = make(map[interface{}]interface{})
		stat.Extra[StatLimitDuration] = time.Duration(limit.GetDuration()) * time.Second
		stat.Extra[StatLimitData] = limit.GetData()
	}

	log.Debugf("incoming relay connection from: %s", src.ID)

	select {
	case c.incoming <- accept{
		conn: &Conn{stream: s, remote: src, stat: stat, client: c},
		writeResponse: func() error {
			return writeResponse(pbv2.Status_OK)
		},
	}:
	case <-time.After(AcceptTimeout):
		handleError(pbv2.Status_CONNECTION_FAILED)
	}
	rd.Close()
}
