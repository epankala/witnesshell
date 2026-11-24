package launch

import (
	"os/user"
	"strconv"
)

// LookupUID returns a local user's id.
func LookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), err
}

// LookupUser returns a local user with all groups.
func LookupUser(uid uint32) (User, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return User{}, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return User{}, err
	}
	out := User{Name: u.Username, Home: u.HomeDir, UID: uid, GID: uint32(gid)}
	gs, err := u.GroupIds()
	if err != nil {
		return User{}, err
	}
	for _, g := range gs {
		id, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return User{}, err
		}
		out.Groups = append(out.Groups, uint32(id))
	}
	return out, nil
}
