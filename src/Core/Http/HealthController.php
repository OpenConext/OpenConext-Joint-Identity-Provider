<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Http;

use JointIdentityProvider\Core\Configuration\CertificateExpiryCheck;
use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\InvalidConfiguration;
use JointIdentityProvider\Core\Storage\TransactionStoreFactory;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

/**
 * Operator monitoring (design §13): configuration validity, certificate expiry and transaction table
 * availability; never configuration values.
 */
final readonly class HealthController
{
    public const string ROUTE = 'jip_health';

    public function __construct(
        private ConfigurationLoader $loader,
        private CertificateExpiryCheck $certificateExpiry,
        private TransactionStoreFactory $stores,
        #[Autowire(service: 'jip.logger')] private LoggerInterface $logger,
    ) {
    }

    #[Route('/health', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(): JsonResponse
    {
        try {
            $configuration = $this->loader->load();
        } catch (InvalidConfiguration $exception) {
            $this->logger->error(
                'JIP configuration is invalid; refusing to serve: {problems}',
                ['problems' => implode('; ', $exception->errors)],
            );

            return new JsonResponse(['status' => 'DOWN'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        try {
            $this->stores->create()->checkAvailability();
        } catch (Throwable $exception) {
            // Database messages may contain credentials; log only the exception class.
            $this->logger->error('JIP transaction store is unavailable ({exception_class})', [
                'exception_class' => $exception::class,
            ]);

            return new JsonResponse(['status' => 'DOWN'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        return new JsonResponse(
            ['status' => 'UP', 'certificates' => $this->certificateExpiry->status($configuration)],
            Response::HTTP_OK,
        );
    }
}
