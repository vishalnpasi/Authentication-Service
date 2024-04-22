package com.albanero.authservice.common.constants;

/**
 * Interface that provides MFA constants for Authenticate API
 * 
 */

public final class MfaConstants {
      public static final String PROVIDERAPP = "Google Authenticator";

      public static final String QR_PREFIX = "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=";
      public static final String ALBANERO_PLATFORM = "Albanero Platform";
      private MfaConstants() {
            throw new IllegalStateException("MfaConstants class");
      }
}
