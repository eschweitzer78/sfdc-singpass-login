public with sharing class SingPass_JWKSController {
    public SingPass_JWKSController() {

    }

    public void tweakHeaders() {
        ApexPages.currentPage().getHeaders().put('Access-Control-Allow-Origin', '*');
        ApexPages.currentPage().getHeaders().put('Access-Control-Allow-Methods', 'POST');
    }
}
