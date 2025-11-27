/**
 * This file contains all necessary Angular controller definitions for creating signature credentials.
 */
(function() {
  'use strict';

  angular.module('frontend.consumers')
    .controller('CreateSignatureCredentialController', [
      '$scope', '$rootScope', '$log','ConsumerService','$uibModalInstance', 'KongErrorService', '_consumer',
      function controller($scope, $rootScope, $log, ConsumerService, $uibModalInstance, KongErrorService, _consumer ) {

        $scope.consumer = _consumer;
        $scope.credentials = {
          client_id: '',
          client_secret: ''
        };
        $scope.errors = {};

        $scope.createSignatureCredential = createSignatureCredential;
        $scope.close = function(){
          $uibModalInstance.dismiss();
        };

        function createSignatureCredential() {
          var body = {};

          if($scope.credentials.client_id) body.client_id = $scope.credentials.client_id;
          if($scope.credentials.client_secret) body.client_secret = $scope.credentials.client_secret;

          ConsumerService.addCredential($scope.consumer.id,'signature-credential',body).then(function(resp){
            $log.debug("Signature credential generated",resp);
            $rootScope.$broadcast('consumer.signature-credential.created');
            $uibModalInstance.dismiss();
          }).catch(function(err){
            $log.error(err);
            KongErrorService.handle($scope, err);
          });
        }
      }
    ])
}());
