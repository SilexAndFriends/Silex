<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests\Provider;

use PHPUnit\Framework\TestCase;
use Silex\Application;
use Silex\Provider\FormServiceProvider;
use Silex\Provider\CsrfServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Silex\Provider\TranslationServiceProvider;
use Silex\Provider\ValidatorServiceProvider;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\AbstractTypeExtension;
use Symfony\Component\Form\Exception\InvalidArgumentException;
use Symfony\Component\Form\FormTypeGuesserChain;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Translation\Exception\NotFoundResourceException;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Form\FormFactory;
use Symfony\Component\Form\Form;
use Symfony\Component\Form\FormRegistry;

class FormServiceProviderTest extends TestCase
{
    public function testFormFactoryServiceIsFormFactory(): void
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        $this->assertInstanceOf(FormFactory::class, $app['form.factory']);
    }

    public function testFormRegistryServiceIsFormRegistry(): void
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        $this->assertInstanceOf(FormRegistry::class, $app['form.registry']);
    }

    public function testFormServiceProviderWillLoadTypes(): void
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend('form.types', function ($extensions) {
            $extensions[] = new DummyFormType();

            return $extensions;
        });

        $form = $app['form.factory']->createBuilder(FormType::class, [])
            ->add('dummy', DummyFormType::class)
            ->getForm();

        $this->assertInstanceOf(Form::class, $form);
    }

    public function testFormServiceProviderWillLoadTypesServices(): void
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app['dummy'] = function () {
            return new DummyFormType();
        };
        $app->extend('form.types', function ($extensions) {
            $extensions[] = 'dummy';

            return $extensions;
        });

        $form = $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('dummy', 'dummy')
            ->getForm();

        $this->assertInstanceOf(Form::class, $form);
    }

    public function testNonExistentTypeService(): void
    {
        $this->expectExceptionMessage("Invalid form type. The silex service \"dummy\" does not exist.");
        $this->expectException(InvalidArgumentException::class);
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend('form.types', function ($extensions) {
            $extensions[] = 'dummy';

            return $extensions;
        });

        $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('dummy', 'dummy')
            ->getForm();
    }

    public function testFormServiceProviderWillLoadTypeExtensions(): void
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend('form.type.extensions', function ($extensions) {
            $extensions[] = new DummyFormTypeExtension();

            return $extensions;
        });

        $form = $app['form.factory']->createBuilder(FormType::class, [])
            ->add('file', FileType::class, ['image_path' => 'webPath'])
            ->getForm();

        $this->assertInstanceOf(Form::class, $form);
    }

    public function testFormServiceProviderWillLoadTypeExtensionsServices(): void
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app['dummy.form.type.extension'] = function () {
            return new DummyFormTypeExtension();
        };
        $app->extend('form.type.extensions', function ($extensions) {
            $extensions[] = 'dummy.form.type.extension';

            return $extensions;
        });

        $form = $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('file', FileType::class, ['image_path' => 'webPath'])
            ->getForm();

        $this->assertInstanceOf(Form::class, $form);
    }

    public function testNonExistentTypeExtensionService(): void
    {
        $this->expectExceptionMessage("Invalid form type extension. The silex service \"dummy.form.type.extension\" does not exist.");
        $this->expectException(InvalidArgumentException::class);

        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend('form.type.extensions', function ($extensions) {
            $extensions[] = 'dummy.form.type.extension';

            return $extensions;
        });

        $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('dummy', 'dummy.form.type')
            ->getForm();
    }

    public function testFormServiceProviderWillLoadTypeGuessers(): void
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend('form.type.guessers', function ($guessers) {
            $guessers[] = new FormTypeGuesserChain([]);

            return $guessers;
        });

        $this->assertInstanceOf(FormFactory::class, $app['form.factory']);
    }

    public function testFormServiceProviderWillLoadTypeGuessersServices(): void
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app['dummy.form.type.guesser'] = function () {
            return new FormTypeGuesserChain([]);
        };
        $app->extend('form.type.guessers', function ($guessers) {
            $guessers[] = 'dummy.form.type.guesser';

            return $guessers;
        });

        $this->assertInstanceOf(FormFactory::class, $app['form.factory']);
    }

    public function testNonExistentTypeGuesserService(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid form type guesser. The silex service \"dummy.form.type.guesser\" does not exist.");

        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend('form.type.guessers', function ($extensions) {
            $extensions[] = 'dummy.form.type.guesser';

            return $extensions;
        });

        $factory = $app['form.factory'];
    }

    public function testFormServiceProviderWillUseTranslatorIfAvailable(): void
    {
        $app = new Application();

        $app->register(new FormServiceProvider());
        $app->register(new TranslationServiceProvider());
        $app['translator.domains'] = [
            'messages' => [
                'de' => [
                    'The CSRF token is invalid. Please try to resubmit the form.' => 'German translation',
                ],
            ],
        ];
        $app['locale'] = 'de';

        $app['csrf.token_manager'] = function () {
            return $this->getMockBuilder(CsrfTokenManagerInterface::class)->getMock();
        };

        $form = $app['form.factory']->createBuilder(FormType::class, [])
            ->getForm();

        $form->handleRequest($req = Request::create('/', 'POST', ['form' => [
            '_token' => 'the wrong token',
        ]]));

        $this->assertFalse($form->isValid());
        $r = new \ReflectionMethod($form, 'getErrors');
        if (!$r->getNumberOfParameters()) {
            $this->assertStringContainsString('ERROR: German translation', $form->getErrorsAsString());
        } else {
            // as of 2.5
            $this->assertStringContainsString('ERROR: German translation', (string) $form->getErrors(true, false));
        }
    }

    public function testFormServiceProviderWillNotAddNonexistentTranslationFiles(): void
    {
        $app = new Application([
            'locale' => 'nonexistent',
        ]);

        $app->register(new FormServiceProvider());
        $app->register(new ValidatorServiceProvider());
        $app->register(new TranslationServiceProvider(), [
            'locale_fallbacks' => [],
        ]);

        $app['form.factory'];
        $translator = $app['translator'];

        try {
            $translator->trans('test');
            $this->addToAssertionCount(1);
        } catch (NotFoundResourceException $e) {
            $this->fail('Form factory should not add a translation resource that does not exist');
        }
    }

    public function testFormCsrf(): void
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        $app->register(new SessionServiceProvider());
        $app->register(new CsrfServiceProvider());
        $app['session.test'] = true;

        $form = $app['form.factory']->createBuilder(FormType::class, [])->getForm();

        $this->assertTrue(isset($form->createView()['_token']));
    }

    public function testUserExtensionCanConfigureDefaultExtensions(): void
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        $app->register(new SessionServiceProvider());
        $app->register(new CsrfServiceProvider());
        $app['session.test'] = true;

        $app->extend('form.type.extensions', function ($extensions) {
            $extensions[] = new FormServiceProviderTest\DisableCsrfExtension();

            return $extensions;
        });
        $form = $app['form.factory']->createBuilder(FormType::class, [])->getForm();

        $this->assertFalse($form->getConfig()->getOption('csrf_protection'));
    }
}

class DummyFormType extends AbstractType
{
}

class DummyFormTypeExtension extends AbstractTypeExtension
{
    public function getExtendedType()
    {
        return FileType::class;
    }

    public static function getExtendedTypes(): iterable
    {
        return [FileType::class];
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefined(['image_path']);
    }

}
