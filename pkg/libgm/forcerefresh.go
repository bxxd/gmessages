package libgm

import "time"

// ForceRefresh mints a fresh tachyon auth token immediately, bypassing the
// expiry-buffer guard inside refreshAuthToken. A long-running headless client
// must refresh on its own schedule: the paired token advertises a ~24h expiry
// but the server invalidates it far sooner (it's tied to the browser companion
// session), and libgm otherwise only refreshes within 1h of the advertised
// expiry — i.e. effectively never. RegisterRefresh re-signs with the ECDSA
// refresh_key (NOT the browser cookies), so this decouples us from the browser.
// Restores the prior expiry on failure so a transient error doesn't strand us.
func (c *Client) ForceRefresh() error {
	saved := c.AuthData.TachyonExpiry
	c.AuthData.TachyonExpiry = time.Now()
	if err := c.refreshAuthToken(nil); err != nil {
		c.AuthData.TachyonExpiry = saved
		return err
	}
	return nil
}
