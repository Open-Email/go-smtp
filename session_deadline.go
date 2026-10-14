package smtp

import "time"

// SetSessionDeadline bounds future command reads and command dispatch with an
// absolute deadline. Expiry sends 421 4.4.2 and closes the connection, including
// for commands handled by the server without a backend callback. It persists
// across re-greetings and STARTTLS. A zero value disables this additional limit.
//
// Backends can set it in NewSession and extend it after successful delivery.
// Updates are safe from other goroutines and apply on the next read or command;
// already-running backend work must enforce its own context/deadline.
func (c *Conn) SetSessionDeadline(deadline time.Time) {
	c.locker.Lock()
	c.sessionDeadline = deadline
	c.locker.Unlock()
}

func (c *Conn) getSessionDeadline() time.Time {
	c.locker.Lock()
	defer c.locker.Unlock()
	return c.sessionDeadline
}
