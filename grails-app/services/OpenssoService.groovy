import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH

class OpenssoService {

   static transactional = false

   String queryOpenSSO (String restAction, Map args) {
      // note - in plugin code, baseurl should be retrieved from the config hash
      def baseurl = CH.config.opensso.baseURL ?: "http://localhost:18080/opensso/identity"

      def restUrl = baseurl + restAction
      def separator = "?"
      args.each { key,val ->
         def encodedVal = java.net.URLEncoder.encode(val,"UTF-8")
         restUrl += "${separator}${key}=${encodedVal}"
         separator = "&"
      }
      return restUrl.toURL().text
   }

   String getCookieNameForToken() {
      def s = queryOpenSSO("/getCookieNameForToken", [:])

      // Server response is in the format "string=TOKENNAME". So we split about the
      // '=' character and return the 2nd entry in the array.
      def r = s.tokenize("=")
      def restResponse = (r[1] =~ /\r\n/).replaceAll('')
      return restResponse
   }

   String authenticate(String userName, String password) {
      def restResponse = ""
      try {
         def s = queryOpenSSO("/authenticate", [ username:userName, password:password ])
         def r = s.tokenize("=")
         restResponse = (r[1] =~ /\r\n/).replaceAll('')
      } catch (java.io.IOException e) {
         restResponse = "FALSE"
      }

      return restResponse
   }

   String isTokenValid(String tokenid) {
      def restResponse = ""
      try {
         def s = queryOpenSSO("/isTokenValid", ["tokenid":tokenid])
         def r = s.tokenize("=")
         restResponse = (r[1] =~ /\r\n/).replaceAll('')
      } catch (java.io.IOException e) {
         restResponse = "false"
      }

      return restResponse
   }

  String logout(String tokenid) {
      def restResponse = ""
      try {
         def s = queryOpenSSO("/logout", ["subjectid":tokenid])
         restResponse = "true"
      } catch (java.io.IOException e) {
         restResponse = "false"
      }

      return restResponse
   }


   String authorize(String uri, String action, String tokenid) {
      def restResponse = ""
      try {
         def s = queryOpenSSO("/authorize", [uri:uri, action:action, subjectid:tokenid])
         def r = s.tokenize("=")
         restResponse = (r[1] =~ /\r\n/).replaceAll('')
      } catch (java.io.IOException e) {
         restResponse = "false"
      }

      return restResponse
   }

   Map allAttributes(String tokenid) {
      def restResponse = ""
      try {
         def s = queryOpenSSO("/attributes", [subjectid:tokenid])
         def r = s.tokenize("\r\n")
         def resMap = [:]
         def currentAttribute = ""
         r.each {
            def t = it.tokenize("=")
            if (t[0].toLowerCase().equals("userdetails.attribute.name")) {
               currentAttribute = t[1]
               resMap[currentAttribute] = []
            } else if (t[0].toLowerCase().equals("userdetails.attribute.value")) {
               int i = it.indexOf('=')
               if (i > 0) {
                  def tmpi = it
                  resMap[currentAttribute].add(tmpi.substring(i+1).trim())
               } else {
                  resMap[currentAttribute].add(tmpi)
               }
            }
         }
         restResponse = resMap
      } catch (java.io.IOException e) {
         restResponse = [:]
      }

      return restResponse
   }

}
