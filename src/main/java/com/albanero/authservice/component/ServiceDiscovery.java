package com.albanero.authservice.component;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.stereotype.Component;

@Component
public class ServiceDiscovery {

	private final DiscoveryClient discoveryClient;

	private final LoadBalancerClient loadBalancerClient;

	@Autowired
	public ServiceDiscovery(DiscoveryClient discoveryClient, LoadBalancerClient loadBalancerClient) {
		this.discoveryClient = discoveryClient;
		this.loadBalancerClient = loadBalancerClient;
	}

	/**
	 * method fetch all the services from discovery server and return service ids
	 * 
	 * @return serviceIds
	 */
	public List<String> fetchAllAvailableServiceIds() {
		return discoveryClient.getServices();
	}

	/**
	 * method accept serviceId example application-name and return List of
	 * ServiceInstance
	 * 
	 * @param serviceId application name
	 * @return List of ServiceInstance
	 */
	public List<ServiceInstance> fetchInstancesByServiceId(String serviceId) {
		return discoveryClient.getInstances(serviceId);
	}

	/**
	 * method accept serviceId example application-name and return ServiceInstance
	 * 
	 * @param serviceId
	 * @return Service Instance
	 */
	public ServiceInstance fetchLoadBalancedInstanceByServiceId(String serviceId) {
		return loadBalancerClient.choose(serviceId);
	}

	/**
	 * method accept serviceId example application-name and return host/ip
	 * 
	 * @param serviceId
	 * @return ip/host
	 */
	public String fetchLoadBalancedUrlByServiceId(String serviceId) {
		ServiceInstance instance = loadBalancerClient.choose(serviceId);
		if (instance == null) {
			return null;
		}
		return instance.getUri().toString();
	}

}
