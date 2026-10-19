package store

import (
	"errors"
	"testing"
)

func TestActiveHubsSurviveReopenAndFollowTheList(t *testing.T) {
	s := openTemp(t)
	a := newHub(t, s, "a", "10.99.0.2")
	b := newHub(t, s, "b", "10.99.0.3")
	r1 := newRouter(t, s, "r1", "10.100.0.10")
	r2 := newRouter(t, s, "r2", "10.100.0.11")
	r3 := newRouter(t, s, "r3", "10.100.0.12")
	for _, r := range []Router{r1, r2, r3} {
		if err := s.SetRouterHubs(r.ID, []string{a.ID, b.ID}); err != nil {
			t.Fatal(err)
		}
	}
	for id, hub := range map[string]string{r1.ID: a.ID, r2.ID: b.ID, r3.ID: a.ID} {
		if err := s.SetRouterActiveHub(id, hub); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetRouterActiveHub(r3.ID, ""); err != nil {
		t.Fatal(err)
	}
	// A hub dropped from the list since must not be seeded as carrying it.
	if err := s.SetRouterHubs(r2.ID, []string{a.ID}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ActiveHubs()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[r1.ID] != a.ID {
		t.Fatalf("active hubs = %v", got)
	}
	if err := s.DeleteRouter(r1.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ActiveHubs(); len(got) != 0 {
		t.Fatalf("released router still active: %v", got)
	}
	if err := s.SetRouterActiveHub("missing", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown router: %v", err)
	}
}

func TestClearRouterActiveHubOnlyMatchingHub(t *testing.T) {
	s := openTemp(t)
	a := newHub(t, s, "a", "10.99.0.2")
	b := newHub(t, s, "b", "10.99.0.3")
	r := newRouter(t, s, "r", "10.100.0.10")
	if err := s.SetRouterHubs(r.ID, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouterActiveHub(r.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearRouterActiveHub(r.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ActiveHubs(); got[r.ID] != a.ID {
		t.Fatalf("clear of another hub removed the active one: %v", got)
	}
	if err := s.ClearRouterActiveHub(r.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ActiveHubs(); len(got) != 0 {
		t.Fatalf("active hub kept: %v", got)
	}
}
