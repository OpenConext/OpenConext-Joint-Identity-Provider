<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\EngineBlock;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Result\DeliveryOutcome;
use JointIdentityProvider\Core\Result\ResultDelivery;
use JointIdentityProvider\Oidc\Jose\Base64Url;
use JsonException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

/**
 * The result call of EngineBlock's SBS interface (design §12, §13): `{"nonce": …}` in, the attributes out,
 * once. Every other answer is an error status without attributes, which stops the login at EngineBlock.
 */
final readonly class AttributesController
{
    public function __construct(
        private ConfigurationLoader $loader,
        private ResultDelivery $delivery,
        private LoggerInterface $logger,
    ) {
    }

    #[Route('/attributes', name: 'jip_sbs_attributes', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $configuration = $this->loader->load();

        if (!ApiTokenAuthenticator::isAuthorized($request, $configuration->engineBlock->apiToken)) {
            return self::error('unauthorized', Response::HTTP_UNAUTHORIZED);
        }

        try {
            $data = json_decode($request->getContent(), true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return self::error('invalid_request', Response::HTTP_BAD_REQUEST);
        }

        $nonce = is_array($data) ? ($data['nonce'] ?? null) : null;
        if (!is_string($nonce) || !Base64Url::isRandomToken($nonce)) {
            return self::error('not_found', Response::HTTP_NOT_FOUND);
        }

        try {
            $outcome = $this->delivery->deliver($nonce, $configuration);
        } catch (Throwable $exception) {
            // Exception messages can contain received values; log only the class.
            $this->logger->error('JIP result: internal_error ({exception_class})', [
                'exception_class' => $exception::class,
            ]);

            return self::error('internal_error', Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return self::answer($outcome);
    }

    private static function answer(DeliveryOutcome $outcome): JsonResponse
    {
        if ($outcome->attributes !== null) {
            return self::respond(['attributes' => $outcome->attributes], Response::HTTP_OK);
        }

        return self::error($outcome->status === Response::HTTP_NOT_FOUND ? 'not_found' : 'forbidden', $outcome->status);
    }

    private static function error(string $error, int $status): JsonResponse
    {
        return self::respond(['error' => $error], $status);
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function respond(array $body, int $status): JsonResponse
    {
        $response = new JsonResponse($body, $status);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
