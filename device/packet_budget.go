// SPDX-License-Identifier: MIT

package device

import (
	"errors"

	"golang.zx2c4.com/wireguard/packetbudget"
)

var errPacketBudget = errors.New("packet buffer budget exhausted or closed")

type inboundDispatch struct {
	peer      *Peer
	control   bool
	container *QueueInboundElementsContainer
}

func (device *Device) queueCapacity(legacy int) int {
	if device.packetBudget == nil {
		return legacy
	}
	return device.packetBudget.Config().QueueEntries
}

// queueRoom is called with admissionMu held. All producers use that mutex;
// consumers can only free capacity between this check and publication.
func queueRoom[T any](queue chan T, control bool) bool {
	limit := cap(queue)
	if !control {
		limit -= packetbudget.ControlSlots
	}
	return len(queue) < limit
}

func (device *Device) admitInbound(peer *Peer, c *QueueInboundElementsContainer, control bool) bool {
	if device.packetBudget == nil {
		if !peer.isRunning.Load() {
			return false
		}
		peer.queue.inbound.c <- c
		device.queue.decryption.c <- c
		return true
	}
	device.admissionMu.Lock()
	defer device.admissionMu.Unlock()
	return device.packetBudget.Admit(func() bool {
		if device.isClosed() || !peer.isRunning.Load() || !queueRoom(peer.queue.inbound.c, control) || !queueRoom(device.queue.decryption.c, control) {
			return false
		}
		peer.queue.inbound.c <- c
		device.queue.decryption.c <- c
		return true
	})
}

func (device *Device) admitOutbound(peer *Peer, c *QueueOutboundElementsContainer) bool {
	if device.packetBudget == nil {
		if !peer.isRunning.Load() {
			return false
		}
		peer.queue.outbound.c <- c
		device.queue.encryption.c <- c
		return true
	}
	device.admissionMu.Lock()
	defer device.admissionMu.Unlock()
	control := outboundControl(c)
	return device.packetBudget.Admit(func() bool {
		if device.isClosed() || !peer.isRunning.Load() || !queueRoom(peer.queue.outbound.c, control) || !queueRoom(device.queue.encryption.c, control) {
			return false
		}
		peer.queue.outbound.c <- c
		device.queue.encryption.c <- c
		return true
	})
}

func outboundControl(c *QueueOutboundElementsContainer) bool {
	for _, elem := range c.elems {
		if len(elem.packet) != 0 {
			return false
		}
	}
	return len(c.elems) > 0
}

func (device *Device) dropOutbound(c *QueueOutboundElementsContainer) {
	for _, elem := range c.elems {
		device.PutMessageBuffer(elem.buffer)
		device.PutOutboundElement(elem)
	}
	device.PutOutboundElementsContainer(c)
}

func (device *Device) newKeepaliveElement() *QueueOutboundElement {
	if device.packetBudget == nil {
		return device.NewOutboundElement()
	}
	buffer := device.packetBudget.Get(MaxMessageSize, true)
	if buffer == nil {
		return nil
	}
	elem := device.GetOutboundElement()
	elem.buffer = (*[MaxMessageSize]byte)(buffer)
	elem.nonce = 0
	return elem
}

func (device *Device) controlBuffer(size int) []byte {
	if device.packetBudget == nil {
		return make([]byte, size)
	}
	return device.packetBudget.Get(size, true)
}

func (device *Device) releaseControlBuffer(buf []byte) {
	if device.packetBudget != nil {
		device.packetBudget.Put(buf)
	}
}

func (device *Device) newPool(newObject func() any) *WaitPool {
	if device.packetBudget == nil {
		return NewWaitPool(PreallocatedBuffersPerPool, newObject)
	}
	return &WaitPool{cacheLimit: device.packetBudget.Config().QueueEntries, newObject: newObject}
}

func (device *Device) clearBudgetCaches() {
	for _, pool := range []*WaitPool{device.pool.inboundElementsContainer, device.pool.outboundElementsContainer, device.pool.inboundElements, device.pool.outboundElements} {
		pool.lock.Lock()
		pool.free = nil
		pool.lock.Unlock()
	}
}

// admitHandshake has no data producers, so the entire queue serves control.
func (device *Device) admitHandshake(elem QueueHandshakeElement) bool {
	publish := func() bool {
		if device.isClosed() {
			return false
		}
		select {
		case device.queue.handshake.c <- elem:
			return true
		default:
			return false
		}
	}
	if device.packetBudget != nil {
		return device.packetBudget.Admit(publish)
	}
	return publish()
}
