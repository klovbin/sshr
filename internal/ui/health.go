package ui

import (
	"image/color"
	"time"

	sshrapp "sshr.dev/internal/app"
)

// healthLoop checks every host at once and then every interval until stop
// is closed, kick asks for a check now, after a host was added or changed
func (s *state) healthLoop(stop <-chan struct{}, kick <-chan struct{}, every time.Duration) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-kick:
		case <-t.C:
		}
		hosts, err := s.store.List()
		if err == nil {
			res := sshrapp.CheckHealthAll(hosts)
			select {
			case s.healthRes <- res:
				s.win.Invalidate()
			case <-stop:
				return
			}
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(every)
	}
}

// setHealth starts or stops the checks
func (s *state) setHealth(on bool) {
	if s.healthStop != nil {
		close(s.healthStop)
		s.healthStop = nil
	}
	s.health = nil
	if !on {
		return
	}
	if s.healthRes == nil {
		s.healthRes = make(chan map[string]sshrapp.Health, 1)
	}
	s.healthStop = make(chan struct{})
	s.healthKick = make(chan struct{}, 1)
	go s.healthLoop(s.healthStop, s.healthKick, s.settings.HealthEvery())
}

// kickHealth asks for a check now, a check already waiting is enough
func (s *state) kickHealth() {
	if s.healthStop == nil {
		return
	}
	select {
	case s.healthKick <- struct{}{}:
	default:
	}
}

// finishHealth takes the results of the last check
func (s *state) finishHealth() {
	select {
	case res := <-s.healthRes:
		if s.healthStop != nil {
			s.health = res
		}
	default:
	}
}

// healthColor is the color of a host's status
var healthColors = map[string]color.NRGBA{
	sshrapp.HealthUp:     colOK,
	sshrapp.HealthDown:   colErr,
	sshrapp.HealthNotSSH: colWarn,
}

func healthColor(state string) color.NRGBA {
	if c, ok := healthColors[state]; ok {
		return c
	}
	return colMutedSoft
}

// healthLabel is the text next to the host name, the latency when it
// answers
func (s *state) healthLabel(r sshrapp.Health) string {
	if r.State == sshrapp.HealthUp {
		return r.Label()
	}
	return s.t("health." + r.State)
}
