package netpol

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func corev1Protocol(p string) corev1.Protocol {
	if p == "" {
		return corev1.ProtocolTCP
	}
	return corev1.Protocol(p)
}

func intstrPort(p int32) intstr.IntOrString {
	return intstr.FromInt(int(p))
}
