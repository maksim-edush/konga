/**
 * Modal controller to display signature credential details without exposing secrets in list view.
 */
(function() {
  'use strict';

  angular.module('frontend.consumers')
    .controller('SignatureCredentialDetailsController', [
      '$scope', '$uibModalInstance', '_cred',
      function controller($scope, $uibModalInstance, _cred) {
        $scope.cred = _cred;
        $scope.close = function () {
          $uibModalInstance.dismiss();
        };
      }
    ])
}());
