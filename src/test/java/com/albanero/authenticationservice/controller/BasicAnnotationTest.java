//package com.albanero.authenticationservice.controller;
//
//import org.junit.After;
//import org.junit.AfterClass;
//import org.junit.Before;
//import org.junit.BeforeClass;
//import org.junit.Test;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//
//public class BasicAnnotationTest {
//
//	private static final Logger LOGGER = LoggerFactory.getLogger(BasicAnnotationTest.class);
//
//	// Run once, e.g. Database connection, connection pool
//	@BeforeClass
//	public static void runOnceBeforeClass() {
//		LOGGER.info("@BeforeClass - runOnceBeforeClass");
//		System.out.println("@BeforeClass - runOnceBeforeClass");
//		print("@BeforeClass - runOnceBeforeClass");
//	}
//
//	// Run once, e.g close connection, cleanup
//	@AfterClass
//	public static void runOnceAfterClass() {
//		LOGGER.info("@AfterClass - runOnceAfterClass");
//		System.out.println("@AfterClass - runOnceAfterClass");
//	}
//
//	// Should rename to @BeforeTestMethod
//	// e.g. Creating an similar object and share for all @Test
//	@Before
//	public void runBeforeTestMethod() {
//		LOGGER.info("@Before - runBeforeTestMethod");
//		System.out.println("@Before - runBeforeTestMethod");
//	}
//
//	// Should rename to @AfterTestMethod
//	@After
//	public void runAfterTestMethod() {
//		LOGGER.info("@After - runAfterTestMethod");
//		System.out.println("@After - runAfterTestMethod");
//	}
//
//	public static void print(String input){
//        System.out.println(input);
//    }
//
//	@Test
//	public void test_method_1() {
//		LOGGER.info("@After - runAfterTestMethod");
//		System.out.println("@Test - test_method_1");
//	}
//
//	@Test
//	public void test_method_2() {
//		LOGGER.info("@Test - test_method_2");
//		System.out.println("@Test - test_method_2");
//	}
//
//}